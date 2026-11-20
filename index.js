// Cloudflare Worker Entrypoint with Static Assets & API Routing

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. API: /api/auth -> OAuth Initiation
    if (url.pathname === '/api/auth') {
      const clientId = env.GITHUB_CLIENT_ID || '__CLIENT_ID__';
      if (!clientId || clientId === '__CLIENT_ID__') {
        return new Response(
          JSON.stringify({ error: 'configuration_error', message: 'GITHUB_CLIENT_ID not configured in Cloudflare build variables' }),
          { status: 500, headers: { 'Content-Type': 'application/json; charset=utf-8' } }
        );
      }
      const state = crypto.randomUUID();
      const scope = 'repo,user';
      const redirectUri = `${url.origin}/api/callback`;
      const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${encodeURIComponent(
        clientId
      )}&scope=${encodeURIComponent(scope)}&state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(
        redirectUri
      )}`;
      const headers = new Headers();
      headers.set('Location', githubAuthUrl);
      headers.set(
        'Set-Cookie',
        `__Host-oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
      );
      return new Response(null, { status: 302, headers });
    }

    // 2. API: /api/callback -> OAuth Callback
    if (url.pathname === '/api/callback') {
      const clearCookieHeader = '__Host-oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
      const noStoreCacheHeaders = {
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        'Pragma': 'no-cache',
        'X-Content-Type-Options': 'nosniff'
      };

      const code = url.searchParams.get('code');
      const queryState = url.searchParams.get('state');
      const cookieHeader = request.headers.get('Cookie') || '';
      const match = cookieHeader.match(/(?:^|;\s*)__Host-oauth_state=([^;]+)/);
      const cookieState = match ? match[1] : null;

      if (!queryState || !cookieState || queryState !== cookieState) {
        return new Response(
          JSON.stringify({ error: 'state_mismatch', message: 'State mismatch or expired' }),
          { status: 403, headers: { 'Content-Type': 'application/json', 'Set-Cookie': clearCookieHeader, ...noStoreCacheHeaders } }
        );
      }

      if (!code) {
        return new Response(
          JSON.stringify({ error: 'missing_code', message: 'Missing code' }),
          { status: 400, headers: { 'Content-Type': 'application/json', 'Set-Cookie': clearCookieHeader, ...noStoreCacheHeaders } }
        );
      }

      const clientId = env.GITHUB_CLIENT_ID || '__CLIENT_ID__';
      const clientSecret = env.GITHUB_CLIENT_SECRET || '__CLIENT_SECRET__';
      if (!clientId || clientId === '__CLIENT_ID__' || !clientSecret || clientSecret === '__CLIENT_SECRET__') {
        return new Response(
          JSON.stringify({ error: 'configuration_error', message: 'OAuth credentials missing in environment' }),
          { status: 500, headers: { 'Content-Type': 'application/json', 'Set-Cookie': clearCookieHeader, ...noStoreCacheHeaders } }
        );
      }

      try {
        const response = await fetch('https://github.com/login/oauth/access_token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'User-Agent': 'SHEMARK-CMS-Auth' },
          body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, code: code })
        });
        const data = await response.json();
        if (data.error || !data.access_token) {
          return new Response(
            JSON.stringify({ error: 'token_exchange_failed', message: 'Token exchange failed', details: data }),
            { status: 401, headers: { 'Content-Type': 'application/json', 'Set-Cookie': clearCookieHeader, ...noStoreCacheHeaders } }
          );
        }

        const token = String(data.access_token);
        const targetOrigin = url.origin;
        const authPayload = { provider: 'github', token: token, targetOrigin: targetOrigin };
        const safePayloadJson = JSON.stringify(authPayload).replace(/</g, '\u003c').replace(/>/g, '\u003e').replace(/&/g, '\u0026');

        const html = `<!doctype html><html><head><meta charset="utf-8"/><title>Authenticating...</title></head><body>
<script id="auth-payload" type="application/json">${safePayloadJson}</script>
<script>
(function(){
  try {
    var data = JSON.parse(document.getElementById("auth-payload").textContent);
    if (!window.opener || window.opener.closed) return;
    function receive(e) {
      if (e.origin !== data.targetOrigin || e.source !== window.opener) return;
      var payload = "authorization:" + data.provider + ":success:" + JSON.stringify({ token: data.token, provider: data.provider });
      window.opener.postMessage(payload, data.targetOrigin);
      window.removeEventListener("message", receive, false);
      window.close();
    }
    window.addEventListener("message", receive, false);
    window.opener.postMessage("authorizing:" + data.provider, data.targetOrigin);
  } catch(e){}
})();
</script>
<p style="text-align:center;font-family:sans-serif;margin-top:2rem;">Authentication successful. Closing window...</p>
</body></html>`;

        return new Response(html, {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Set-Cookie': clearCookieHeader, ...noStoreCacheHeaders }
        });
      } catch (err) {
        return new Response(
          JSON.stringify({ error: 'server_exception', message: err.message }),
          { status: 500, headers: { 'Content-Type': 'application/json', 'Set-Cookie': clearCookieHeader, ...noStoreCacheHeaders } }
        );
      }
    }

    // 3. Static Assets: Serve from env.ASSETS (public folder)
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response('Not Found', { status: 404 });
  }
};
