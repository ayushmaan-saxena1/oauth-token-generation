# JWT Token Generation Node Server

This is just for PoC references and not for actual production use. Please use this carefully.

---

## Features
- Generate JWT tokens (user and guest)
- OIDC metadata endpoint
- JWKS endpoint for public key discovery
- Userinfo endpoint (dummy)
- PEM public/private key endpoints
- Info page (renders this README as HTML)

---


## ServiceNow IdP Integration Example

1. Go to **Multi-Provider SSO → Identity Provider**.
2. Click **New**.
3. Select **OpenID Connect**.
4. Fill in:
   - **Name:** `JWT Idp`
   - **Client ID:** `embeddables_token`
   - **Client Secret:** `12345678`
   - **Well Known Configuration URL:** `https://token-generation.onrender.com/.well-known/openid-configuration`

---

## Endpoints

- `/generate-token?email=<email>` - Generate JWT token based on email
- `/generate-guest-token` - Generate guest JWT token
- `/generate-verified-guest-token?token=<captcha_token>` - Generate a guest JWT token only after successful Cloudflare Turnstile CAPTCHA verification. Requires a valid CAPTCHA token in the query string.
- `/userinfo` - Shows the currently logged-in user's info (HTML) with an option to logout in case of logged in user


---

## Usage on third party sites

You can use this IdP to authenticate users on static sites by requesting a JWT for a user-provided email. Here’s a sample function and usage:

````html
<script type="module">
import { init , login , logout } from 'https://<sn_instance_url>/uxasset/externals/sn_embeddable_core/index.jsdbx';

await init({
	theme: '31bf91ae07203010e03948f78ad30095',  /* sys_id of the theme to use for the embeddable components in your website*/
	baseURL: '<sn_instance_url>', /* Base URL of the instance to be used for the embeddable components in your website*/
	authCallback: getTokenCallBack, /* Function which returns the auth token for the current user, required for auth setup*/
});
function getTokenCallBack() {
	var idToken; /* Get the id token for the current user */
	return Promise.resolve(idToken);
}
/* Uncomment below functions to handle login and logout once the user logs into your website */
// await login();
// await logout();

// Call this function with the user's email to get a JWT
async function getJwtToken(email) {
  const response = await fetch(`https://token-generation.onrender.com/generate-token?email=${encodeURIComponent(email)}`);
  const data = await response.json();
  return data.token; // JWT string
}
var generatedIDToken = '';

// Example usage:
document.getElementById('loginBtn').onclick = async function() {
  const email = document.getElementById('emailInput').value;
  generatedIDToken = await getJwtToken(email);
  await login(); // call the SN authentication function after getting the JWT token
  // Store the token, use it in Authorization headers, etc.
  console.log('JWT:', generatedIDToken);
  // Hide input/button and show success message
  document.getElementById('loginForm').style.display = 'none';
  document.getElementById('loginStatus').innerText = email + ' logged in successfully.';
};
</script>



<!-- Example HTML -->
<div id="loginForm">
  <input id="emailInput" type="email" placeholder="Enter your email" />
  <button id="loginBtn">Login</button>
</div>
<div id="loginStatus" style="margin-top:1em;font-weight:bold;"></div>
````

- The user enters their email and clicks "Login".
- After successful login, the input and button are hidden and a message is shown.
- The function fetches a JWT from the IdP and returns it to the website for authentication or API calls.
- The JWT is then used to authenticate the user in the ServiceNow instance.

