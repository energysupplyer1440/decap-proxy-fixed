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
    const token = result.access_token;
    res.send(`<!DOCTYPE html><html><head><script>
      window.opener.postMessage('authorization:github:success:${JSON.stringify({ token })}', '*');
      window.addEventListener('message', function() {
        window.opener.postMessage('authorizing:github', '*');
      });
    </script></head><body><p>Authorizing Decap...</p></body></html>`);
  } catch (e) {
    res.status(500).send('Auth failed: ' + e.message);
  }
});

app.listen(PORT, () => console.log('Proxy listening on port', PORT));
