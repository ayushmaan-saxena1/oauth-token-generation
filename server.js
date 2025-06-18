require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cors = require('cors');
const marked = require('marked');

const app = express();
app.use(express.json());
app.use(cors());

// Info endpoint: show README.md as HTML
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

// Generate kid from the public key
const generateKid = (publicKey) => {
  const hash = crypto.createHash('sha256');
  hash.update(publicKey);
  return hash.digest('hex');
};

// Load keys from local files at startup
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

// 1. Generate token based on email provided
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
    aud: 'embeddables_token',
    iss: 'http://localhost:3000',
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

// 2. Generate basic JWT token without any sub claim
app.get('/generate-guest-token', async (req, res) => {
  if (!guestPrivateKey || !guestKid) {
    return res.status(500).json({ error: 'Guest keys not loaded' });
  }
  const payload = {};
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

// Metadata endpoint (OIDC style)
app.get('/.well-known/openid-configuration', (req, res) => {
  const issuer = `http://${req.get('host')}`;
  const config = {
    issuer,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/generate-token`,
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

// JWKS endpoint (serves main public key)
app.get('/.well-known/jwks.json', (req, res) => {
  // Parse the PEM public key to get modulus and exponent
  const jwk = pemToJwk(publicKey, kid);
  res.json({ keys: [jwk] });
});

// Dummy userinfo endpoint
app.get('/userinfo', (req, res) => {
  // In real IdP, you'd extract user from token
  res.json({
    sub: 'user@example.com',
    email: 'user@example.com',
    name: 'Test User'
  });
});

// Helper: Convert PEM public key to JWK (minimal, RSA only)
function pemToJwk(pem, kid) {
  // Remove header/footer and newlines
  const b64 = pem
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\n/g, '');
  const der = Buffer.from(b64, 'base64');
  // Parse modulus and exponent (simple, not robust for all key types)
  // This is a minimal approach for 2048-bit RSA keys
  // For production, use a library like 'pem-jwk' or 'node-jose'
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


// Public/private key endpoints
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

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
