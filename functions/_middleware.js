// Cloudflare Pages Function Middleware: /functions/_middleware.js
// Precision Gating & Fail-Closed Protection for Confidential Previews & Draft Assets

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // 1. Precise Public Compiled Asset Whitelist (Allowed without Authentication)
  const isPublicCompiledBundle =
    url.pathname.startsWith('/assets/index-') ||
    url.pathname.startsWith('/assets/favicon.') ||
    url.pathname.startsWith('/assets/images/aw001/aw-001-main.webp') ||
    url.pathname.startsWith('/assets/images/radiant-becoming/silk-scarf-mockup.jpg') ||
    url.pathname.startsWith('/assets/images/radiant-becoming/gaiter-mockup.jpg') ||
    url.pathname.startsWith('/assets/images/radiant-becoming/scrunchie-mockup.jpg') ||
    url.pathname.startsWith('/assets/images/radiant-becoming/art-scarf-framed.jpg');

  // Allow public compiled bundles directly
  if (isPublicCompiledBundle) {
    return next();
  }

  // 2. Identify if Request is on Cloudflare Preview Domain (*.pages.dev) or Targeting Confidential Asset Folders
  const isPreviewDomain = url.hostname.includes('.pages.dev');
  const isConfidentialAsset =
    url.pathname.startsWith('/assets/images/uploads/') ||
    url.pathname.startsWith('/assets/images/drafts/');

  // 3. Enforce Authentication on Preview Domains & Confidential Assets
  if (isPreviewDomain || isConfidentialAsset) {
    const authUser = env.PREVIEW_AUTH_USER || 'shemark-admin';
    const authPass = env.PREVIEW_AUTH_PASSWORD;

    // Fail-Closed: If password is not configured in environment, fail securely with HTTP 503
    if (!authPass) {
      return new Response(
        'Confidential Preview: Access Disabled (Environment password not configured).',
        {
          status: 503,
          headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'X-Robots-Tag': 'noindex, nofollow'
          }
        }
      );
    }

    const authHeader = request.headers.get('Authorization');

    // Missing or non-Basic header -> 401 Unauthorized
    if (!authHeader || !authHeader.startsWith('Basic ')) {
      return new Response('Confidential Preview: Authentication Required.', {
        status: 401,
        headers: {
          'WWW-Authenticate': 'Basic realm="SHEMARK Living Confidential Preview"',
          'Content-Type': 'text/plain; charset=utf-8',
          'X-Robots-Tag': 'noindex, nofollow'
        }
      });
    }

    const base64Credentials = authHeader.split(' ')[1];
    let credentials = '';
    try {
      credentials = atob(base64Credentials);
    } catch {
      return new Response('Bad Request: Invalid Base64 Authorization format.', {
        status: 400,
        headers: {
          'Content-Type': 'text/plain; charset=utf-8'
        }
      });
    }

    const [user, pass] = credentials.split(':');

    // Incorrect username or password -> 401 Unauthorized
    if (user !== authUser || pass !== authPass) {
      return new Response('Unauthorized: Invalid preview credentials.', {
        status: 401,
        headers: {
          'WWW-Authenticate': 'Basic realm="SHEMARK Living Confidential Preview"',
          'Content-Type': 'text/plain; charset=utf-8'
        }
      });
    }
  }

  // 4. Continue to Next Handler & Inject NoIndex on Preview Domains
  const response = await next();

  if (isPreviewDomain) {
    response.headers.set('X-Robots-Tag', 'noindex, nofollow');
  }

  return response;
}
