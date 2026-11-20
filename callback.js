// Cloudflare Pages Function: /functions/api/callback.js
// Standard-Compliant OAuth Callback with Authoritative Origin Whitelist, Sanitized Errors & Cache Control

// Helper to validate whether request origin matches SHEMARK approved CMS origins
function isAllowedCmsOrigin(origin, env) {
  if (!origin) return false;

  // 1. Authoritative explicit environment whitelist (no broader fallback when configured)
  if (env && env.CMS_ALLOWED_ORIGINS) {
    const list = env.CMS_ALLOWED_ORIGINS.split(',').map((item) => item.trim()).filter(Boolean);
    return list.includes(origin);
  }

  // 2. Local development exception (strictly restricted to explicitly enabled local testing)
  if (env && env.ALLOW_LOCAL_CMS === 'true') {
    try {
      const parsed = new URL(origin);
      const host = parsed.hostname;
      const protocol = parsed.protocol;
      if ((protocol === 'http:' || protocol === 'https:') && (host === 'localhost' || host === '127.0.0.1')) {
        return true;
      }
    } catch {
      return false;
    }
  }

  // 3. Fail-Closed Default: If CMS_ALLOWED_ORIGINS is not set and local dev is not enabled, reject all origins
  return false;
}

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  // Common security headers for all response branches
  const clearCookieHeader = '__Host-oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
  const noStoreCacheHeaders = {
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'Pragma': 'no-cache',
    'X-Content-Type-Options': 'nosniff'
  };

  // 1. Validate Target Origin against Explicit Authoritative Whitelist (Least-Privilege Origin Protection)
  const targetOrigin = url.origin;
  if (!isAllowedCmsOrigin(targetOrigin, env)) {
    return new Response(
      JSON.stringify({
        error: 'untrusted_cms_origin',
        message: 'Security Alert: Callback origin is not in the approved SHEMARK CMS origin whitelist.'
      }),
      {
        status: 403,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': clearCookieHeader,
          ...noStoreCacheHeaders
        }
      }
    );
  }

  const code = url.searchParams.get('code');
  const queryState = url.searchParams.get('state');

  // Parse __Host-oauth_state from request Cookie header
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/(?:^|;\s*)__Host-oauth_state=([^;]+)/);
  const cookieState = match ? match[1] : null;

  // 2. Validate State Existence & Match (CSRF & Session Binding Defense)
  if (!queryState || !cookieState || queryState !== cookieState) {
    return new Response(
      JSON.stringify({
        error: 'state_mismatch_or_expired',
        message: 'Security Alert: OAuth state parameter is missing, mismatched, or expired. Request rejected.'
      }),
      {
        status: 403,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': clearCookieHeader,
          ...noStoreCacheHeaders
        }
      }
    );
  }

  // 3. Validate Authorization Code
  if (!code) {
    return new Response(
      JSON.stringify({
        error: 'missing_code',
        message: 'Bad Request: Missing GitHub authorization code.'
      }),
      {
        status: 400,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': clearCookieHeader,
          ...noStoreCacheHeaders
        }
      }
    );
  }

  const clientId = env.GITHUB_CLIENT_ID;
  const clientSecret = env.GITHUB_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    return new Response(
      JSON.stringify({
        error: 'configuration_error',
        message: 'Server Configuration Error: OAuth credentials missing in environment.'
      }),
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': clearCookieHeader,
          ...noStoreCacheHeaders
        }
      }
    );
  }

  try {
    // 4. Single-Use Code Exchange with GitHub API
    const response = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'User-Agent': 'SHEMARK-Living-Decap-Auth-Bridge'
      },
      body: JSON.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        code: code
      })
    });

    const data = await response.json();

    if (data.error || !data.access_token) {
      return new Response(
        JSON.stringify({
          error: 'token_exchange_failed',
          message: 'GitHub OAuth token exchange was rejected or invalid.'
        }),
        {
          status: 401,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            'Set-Cookie': clearCookieHeader,
            ...noStoreCacheHeaders
          }
        }
      );
    }

    const token = String(data.access_token);
    const provider = 'github';

    // 5. Context-Safe JSON Serialization to Eliminate Script-Context Breakout & Injection
    const authPayload = {
      provider: provider,
      token: token,
      targetOrigin: targetOrigin
    };

    // Sanitize JSON by escaping <, >, &, and Unicode line separators to prevent HTML/script breakout
    const safePayloadJson = JSON.stringify(authPayload)
      .replace(/</g, '\\u003c')
      .replace(/>/g, '\\u003e')
      .replace(/&/g, '\\u0026')
      .replace(/\u2028/g, '\\u2028')
      .replace(/\u2029/g, '\\u2029');

    // 6. Secure PostMessage Delivery via Non-Executable JSON Island & DOM Validation
    const content = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta http-equiv="X-Content-Type-Options" content="nosniff" />
    <title>Authenticating with SHEMARK CMS...</title>
  </head>
  <body>
    <script id="auth-payload" type="application/json">${safePayloadJson}</script>
    <script>
      (function() {
        try {
          var payloadElement = document.getElementById("auth-payload");
          if (!payloadElement) return;
          var data = JSON.parse(payloadElement.textContent);
          var targetOrigin = data.targetOrigin;
          var provider = data.provider;
          var token = data.token;

          if (!window.opener || window.opener.closed) {
            document.body.innerHTML = '<p style="font-family: sans-serif; text-align: center; margin-top: 2rem; color: #b91c1c;">Authentication Error: CMS window opener was not found or was closed. Please re-open login from CMS.</p>';
            return;
          }

          function receiveMessage(e) {
            if (e.origin !== targetOrigin) {
              return;
            }
            if (e.source !== window.opener) {
              return;
            }
            var messagePayload = "authorization:" + provider + ":success:" + JSON.stringify({
              token: token,
              provider: provider
            });
            window.opener.postMessage(messagePayload, targetOrigin);
            window.removeEventListener("message", receiveMessage, false);
            window.close();
          }

          window.addEventListener("message", receiveMessage, false);
          window.opener.postMessage("authorizing:" + provider, targetOrigin);
        } catch (err) {
          document.body.innerHTML = '<p style="font-family: sans-serif; text-align: center; margin-top: 2rem; color: #b91c1c;">Authentication processing error.</p>';
        }
      })();
    </script>
    <p style="font-family: sans-serif; text-align: center; margin-top: 2rem; color: #4b5563;">
      Authentication handshake in progress. Closing window...
    </p>
  </body>
</html>`;

    return new Response(content, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=UTF-8',
        'Set-Cookie': clearCookieHeader,
        ...noStoreCacheHeaders
      }
    });
  } catch (err) {
    return new Response(
      JSON.stringify({
        error: 'server_exception',
        message: 'Internal server error occurred during authentication processing.'
      }),
      {
        status: 500,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': clearCookieHeader,
          ...noStoreCacheHeaders
        }
      }
    );
  }
}
