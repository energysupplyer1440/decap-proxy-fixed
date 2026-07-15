const express = require('express');
const { AuthorizationCode } = require('simple-oauth2');

const app = express();
const PORT = process.env.PORT || 3000;

const client = new AuthorizationCode({
  client: {
    id: process.env.GITHUB_OAUTH_ID,
    secret: process.env.GITHUB_OAUTH_SECRET,
  },
  auth: {
    tokenHost: 'https://github.com',
    tokenPath: '/login/oauth/access_token',
    authorizePath: '/login/oauth/authorize',
  },
});

app.get('/auth', (req, res) => {
  const provider = req.query.provider;
  if (provider !== 'github') return res.status(400).send('Invalid provider');

  const scope = 'repo,user';
  const redirectUri = `https://${req.hostname}/callback?provider=github`;
  const authUrl = client.authorizeURL({
    redirect_uri: redirectUri,
    scope,
    state: Math.random().toString(36).slice(2, 10),
  });
  res.redirect(authUrl);
});

app.get('/callback', async (req, res) => {
  const { code, provider } = req.query;
  if (provider !== 'github') return res.status(400).send('Invalid provider');
  if (!code) return res.status(400).send('Missing code');

  try {
    const result = await client.getToken({
      code,
      redirect_uri: `https://${req.hostname}/callback?provider=github`,
    });
    const accessTokenData = result.token;
    const token = accessTokenData.access_token;

    // Popup communication: wait for parent to send message, then send token back
    res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Authorizing...</title>
</head>
<body>
  <p>Authorizing Decap...</p>
  <script>
    var token = ${JSON.stringify(token)};
    function sendMessage() {
      window.opener.postMessage('authorization:github:success:' + JSON.stringify({ token: token }), '*');
    }
    window.addEventListener('message', function() {
      sendMessage();
      window.close();
    });
    window.opener.postMessage('authorizing:github', '*');
  </script>
</body>
</html>`);
  } catch (e) {
    res.status(500).send('Auth failed: ' + e.message);
  }
});

app.listen(PORT, () => console.log('Proxy listening on port', PORT));
