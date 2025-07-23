require('dotenv').config();
const express = require('express');

// Relying on https://render.com/docs/environment-variables#default-environment-variables for switching between local and render env
const IS_RENDER = process.env.RENDER === 'true';
console.log('IS_RENDER:', IS_RENDER);

const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cors = require('cors');
const marked = require('marked');
const fetch = require('node-fetch');
const app = express();
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

// Session middleware setup
const session = require('express-session');
app.use(session({
  secret: process.env.SESSION_SECRET || 'change_this_secret',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: IS_RENDER },
}));

app.get('/', (req, res) => {
  try {
    const readmePath = path.resolve(__dirname, 'README.md');
    const markdown = fs.readFileSync(readmePath, 'utf8');
    const html = marked.parse(markdown);
    res.send(`
      <html>
        <head>
          <title>JWT Token Generation Node Server</title>
          <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; background: #fafbfc; color: #222; }
            pre { background: #eee; padding: 10px; border-radius: 4px; }
            code { background: #eee; padding: 2px 4px; border-radius: 3px; }
            h1, h2, h3 { color: #222; }
            a { color: #0366d6; }
          </style>
        </head>
        <body>${html}</body>
      </html>
    `);
  } catch (err) {
    res.type('text/plain').send('README.md not found or could not be rendered.');
  }
});

const PORT = process.env.PORT || 3000;

let privateKey, publicKey, kid;
let guestPrivateKey, guestPublicKey, guestKid;

const generateKid = (publicKey) => {
  const hash = crypto.createHash('sha256');
  hash.update(publicKey);
  return hash.digest('hex');
};

try {
  privateKey = fs.readFileSync(path.resolve(process.env.PRIVATE_KEY_PATH), 'utf8');
  publicKey = fs.readFileSync(path.resolve(process.env.PUBLIC_KEY_PATH), 'utf8');
  kid = generateKid(publicKey);
  guestPrivateKey = fs.readFileSync(path.resolve(process.env.GUEST_PRIVATE_KEY_PATH), 'utf8');
  guestPublicKey = fs.readFileSync(path.resolve(process.env.GUEST_PUBLIC_KEY_PATH), 'utf8');
  guestKid = generateKid(guestPublicKey);
} catch (error) {
  console.error('Error loading key files:', error);
}

app.get('/generate-token', async (req, res) => {
  const { email } = req.query;
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  if (!privateKey || !kid) {
    await downloadKeys();
  }
  const payload = {
    sub: email,
    email: email,
    aud: IS_RENDER ? 'embeddables_token' : 'embeddables_token_local',
    iss: IS_RENDER ? `https://${req.get('host')}` : 'http://localhost:3000',
    scope: 'read:messages write:messages',
    iat: Math.floor(Date.now() / 1000)
  };
  const jwtOptions = {
    algorithm: 'RS256',
    expiresIn: '1h',
    keyid: kid,
  };
  try {
    const token = jwt.sign(payload, privateKey, jwtOptions);
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate token' });
  }
});

app.get('/generate-guest-token', async (req, res) => {
  if (!guestPrivateKey || !guestKid) {
    return res.status(500).json({ error: 'Guest keys not loaded' });
  }
  const payload = {
    aud:"embeddables-guest-token",
    iss:"embeddables-guest-token"
  };
  const jwtOptions = {
    algorithm: 'RS256',
    expiresIn: '1h',
    keyid: guestKid,
  };
  try {
    const token = jwt.sign(payload, guestPrivateKey, jwtOptions);
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate guest token' });
  }
});

app.get('/generate-verified-guest-token', async (req, res) => {
  const token = req.query.token;
  const ip = req.headers['cf-connecting-ip'] || req.ip;

  if (!token) {
    return res.status(400).json({ error: 'Missing CAPTCHA token' });
  }

  if (!guestPrivateKey || !guestKid) {
    return res.status(500).json({ error: 'Guest keys not loaded' });
  }

  const captchaSuccess = await validateCaptcha(token, ip);
  if (!captchaSuccess) {
    return res.status(403).json({ error: 'CAPTCHA verification failed' });
  }

  const payload = {
    aud: 'embeddables-guest-token',
    iss: 'embeddables-guest-token',
    captchaVerified: captchaSuccess
  };

  const jwtOptions = {
    algorithm: 'RS256',
    expiresIn: '1h',
    keyid: guestKid
  };

  try {
    const signedToken = jwt.sign(payload, guestPrivateKey, jwtOptions);
    res.json({ token: signedToken });
  } catch (error) {
    res.status(500).json({ error: 'Failed to generate guest token' });
  }
});
// cloudflare turnstile secret key
// This is the demo secret key. In production, we recommend
// you store your secret key(s) safely.
const SECRET_KEY = "0x4AAAAAABlmGnsA_ZQZ83YH6Vg-vHCH43s";
async function validateCaptcha(token, ip) {
  const url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      secret: SECRET_KEY,
      response: token,
      remoteip: ip
    })
  });

  const result = await response.json();
  return result.success;
}



app.get('/.well-known/openid-configuration', (req, res) => {
  const issuer = IS_RENDER ? `https://${req.get('host')}` : 'http://localhost:3000';
  const config = {
    issuer,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    response_types_supported: ['code', 'token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email'],
    claims_supported: ['sub', 'aud', 'iss', 'scope', 'email', 'iat', 'exp'],
    grant_types_supported: ['authorization_code', 'implicit']
  };
  res.json(config);
});

app.get('/.well-known/jwks.json', (req, res) => {
  const jwk = pemToJwk(publicKey, kid);
  res.json({ keys: [jwk] });
});

const codeStore = {};

app.get('/authorize', (req, res) => {
  const { client_id, redirect_uri, state, scope, response_type } = req.query;
  if (req.session && req.session.email) {
    const code = Math.random().toString(36).substr(2, 16);
    codeStore[code] = {
      email: req.session.email,
      client_id,
      redirect_uri,
      scope,
      created: Date.now(),
    };
    const redirectUrl = `${redirect_uri}?code=${code}${state ? `&state=${encodeURIComponent(state)}` : ''}`;
    return res.redirect(redirectUrl);
  }
  res.send(`
    <html>
      <head>
        <title>Login - OIDC Authorization</title>
        <style>
          body { font-family: Arial, sans-serif; background: #f6f6f6; margin: 0; padding: 0; }
          .container { max-width: 400px; margin: 80px auto; background: #fff; padding: 32px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.07); }
          input[type=email], button { width: 100%; padding: 10px; margin-top: 8px; border-radius: 4px; border: 1px solid #ccc; }
          button { background: #0366d6; color: #fff; border: none; margin-top: 16px; cursor: pointer; }
          h2 { margin-bottom: 16px; }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>Sign in to continue</h2>
          <form method="POST" action="/authorize">
            <input type="hidden" name="client_id" value="${client_id || ''}" />
            <input type="hidden" name="redirect_uri" value="${redirect_uri || ''}" />
            <input type="hidden" name="state" value="${state || ''}" />
            <input type="hidden" name="scope" value="${scope || ''}" />
            <input type="hidden" name="response_type" value="${response_type || ''}" />
            <label for="email">Email:</label>
            <input type="email" id="email" name="email" required autofocus />
            <button type="submit">Continue</button>
          </form>
        </div>
      </body>
    </html>
  `);
});

app.post('/authorize', (req, res) => {
  const { email, client_id, redirect_uri, state, scope, response_type } = req.body;
  if (!email || !redirect_uri) {
    return res.status(400).send('Missing email or redirect_uri');
  }
  req.session.email = email;
  const code = Math.random().toString(36).substr(2, 16);
  codeStore[code] = {
    email,
    client_id,
    redirect_uri,
    scope,
    created: Date.now(),
  };
  const redirectUrl = `${redirect_uri}?code=${code}${state ? `&state=${encodeURIComponent(state)}` : ''}`;
  res.redirect(redirectUrl);
});

app.get('/userinfo', (req, res) => {
  if (!req.session || !req.session.email) {
    return res.send('<h2>No user is logged in.</h2>');
  }
  const email = req.session.email;
  res.send(`
    <h2>User Info</h2>
    <p><strong>Email:</strong> ${email}</p>
    <form method="POST" action="/logout" style="margin-top:20px;">
      <button type="submit">Logout</button>
    </form>
  `);
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/userinfo');
  });
});

function pemToJwk(pem, kid) {
  const b64 = pem
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\n/g, '');
  const der = Buffer.from(b64, 'base64');
  const modulusStart = der.indexOf(Buffer.from([0x02, 0x82])) + 4;
  const modulusLen = der.readUInt16BE(modulusStart - 2);
  const modulus = der.slice(modulusStart, modulusStart + modulusLen);
  const exponentStart = modulusStart + modulusLen + 2;
  const exponentLen = der[exponentStart - 1];
  const exponent = der.slice(exponentStart, exponentStart + exponentLen);
  return {
    kty: 'RSA',
    kid,
    use: 'sig',
    alg: 'RS256',
    n: modulus.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'),
    e: exponent.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  };
}


app.get('/public-key', (req, res) => {
  res.type('text/plain').send(publicKey);
});
app.get('/private-key', (req, res) => {
  res.type('text/plain').send(privateKey);
});
app.get('/guest-public-key', (req, res) => {
  res.type('text/plain').send(guestPublicKey);
});
app.get('/guest-private-key', (req, res) => {
  res.type('text/plain').send(guestPrivateKey);
});

app.get('/guest-certificate', (req, res) => {
  const certPath = path.resolve(__dirname, 'guest_public.crt');
  try {
    const cert = fs.readFileSync(certPath, 'utf8');
    res.type('application/x-pem-file').send(cert);
  } catch (err) {
    res.status(404).send('Guest certificate not found.');
  }
});

app.post('/token', (req, res) => {
  const { grant_type, code, redirect_uri, client_id } = req.body;
  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }
  if (!code || !redirect_uri || !client_id) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Missing parameters' });
  }
  const codeData = codeStore[code];
  if (!codeData) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid or expired code' });
  }
  if (codeData.redirect_uri !== redirect_uri || codeData.client_id !== client_id) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri or client_id mismatch' });
  }
  delete codeStore[code];
  const issuer = IS_RENDER ? `https://${req.get('host')}` : 'http://localhost:3000';
  const payload = {
    sub: codeData.email,
    email: codeData.email,
    aud: client_id,
    iss: issuer,
    scope: codeData.scope,
    iat: Math.floor(Date.now() / 1000),
  };
  const jwtOptions = {
    algorithm: 'RS256',
    expiresIn: '1h',
    keyid: kid,
  };
  let id_token;
  try {
    id_token = jwt.sign(payload, privateKey, jwtOptions);
  } catch (e) {
    console.error('JWT signing error:', e);
    return res.status(500).json({ error: 'server_error', error_description: 'Failed to sign token' });
  }
  res.json({
    access_token: id_token,
    id_token,
    token_type: 'Bearer',
    expires_in: 3600,
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
