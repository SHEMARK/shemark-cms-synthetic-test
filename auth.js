// Cloudflare Pages Function: /functions/api/auth.js
// Standard-Compliant OAuth Initiation with RFC 6265bis __Host- Cookie State Binding

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const clientId = env.GITHUB_CLIENT_ID;
  if (!clientId) {
    return new Response(
      JSON.stringify({
        error: 'configuration_error',
        message: 'Server Configuration Error: GITHUB_CLIENT_ID is not configured in environment.'
      }),
      {
        status: 500,
        headers: { 'Content-Type': 'application/json; charset=utf-8' }
      }
    );
  }

  // Generate cryptographically secure state nonce
  const state = crypto.randomUUID();

  // Scopes required for Decap CMS: 'repo' for private/public content commits, 'user' for identity
  const scope = 'repo,user';

  const redirectUri = `${url.origin}/api/callback`;
  const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${encodeURIComponent(
    clientId
  )}&scope=${encodeURIComponent(scope)}&state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(
    redirectUri
  )}`;

  // Standards-Compliant RFC 6265bis __Host- Cookie configuration:
  // 1. Must have Secure attribute
  // 2. Must be sent from secure origin
  // 3. Must have Path=/ (mandatory for __Host- prefix)
  // 4. Must NOT have Domain attribute
  const headers = new Headers();
  headers.set('Location', githubAuthUrl);
  headers.set(
    'Set-Cookie',
    `__Host-oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`
  );

  return new Response(null, {
    status: 302,
    headers
  });
}
