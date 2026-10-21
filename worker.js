const SESSION_COOKIE = "xyzw_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days
const LOGIN_PATH = "/__login";

const encoder = new TextEncoder();

/** Base64url without padding, so the value is safe inside a cookie. */
function base64UrlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlDecode(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

/**
 * Derive the HMAC-SHA-256 key from ADMIN_PASSWORD.
 * @param {string} password The configured admin password.
 * @returns {Promise<CryptoKey>} Key usable with crypto.subtle.sign/verify.
 */
async function sessionKey(password) {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/**
 * Produce "<expiry>.<signature>" for the session cookie.
 * @param {string} password The configured admin password.
 * @returns {Promise<string>} Cookie value, without the "name=" prefix.
 */
async function signSession(password) {
  const expiry = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  const mac = await crypto.subtle.sign(
    "HMAC",
    await sessionKey(password),
    encoder.encode(String(expiry)),
  );
  return `${expiry}.${base64UrlEncode(new Uint8Array(mac))}`;
}

/**
 * Verify a session cookie's signature and expiry.
 * @param {string|null} value Raw cookie value.
 * @param {string} password The configured admin password.
 * @returns {Promise<boolean>} True when the cookie is authentic and unexpired.
 */
async function verifySession(value, password) {
  if (!value) return false;

  const separator = value.lastIndexOf(".");
  if (separator <= 0) return false;

  const expiry = value.slice(0, separator);
  const signature = value.slice(separator + 1);

  const expirySeconds = Number(expiry);
  if (!Number.isInteger(expirySeconds)) return false;
  if (expirySeconds < Math.floor(Date.now() / 1000)) return false;

  let expected;
  try {
    expected = base64UrlDecode(signature);
  } catch {
    return false;
  }

  return crypto.subtle.verify(
    "HMAC",
    await sessionKey(password),
    expected,
    encoder.encode(expiry),
  );
}

/**
 * Compare two strings without leaking their difference through timing.
 * @param {string} provided Value taken from the request.
 * @param {string} expected Value taken from the environment.
 * @returns {boolean} True when both strings are byte-for-byte identical.
 */
function timingSafeEqual(provided, expected) {
  if (provided.length !== expected.length) return false;
  let diff = 0;
  for (let index = 0; index < provided.length; index += 1) {
    diff |= provided.charCodeAt(index) ^ expected.charCodeAt(index);
  }
  return diff === 0;
}

function readCookie(request, name) {
  for (const part of (request.headers.get("Cookie") || "").split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) {
      return part.slice(separator + 1).trim();
    }
  }
  return null;
}

/** Escape text for safe interpolation into the login page HTML. */
function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });
}

/**
 * Build the single-password login page.
 * @param {{message?: string, next?: string}} options Error text and post-login redirect target.
 * @returns {Response} HTML page containing only a password field.
 */
function loginPage({ message = "", next = "/" } = {}) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>请输入密码</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex;
    align-items: center; justify-content: center;
    font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
    background: #f5f6f8; color: #1d2129;
  }
  @media (prefers-color-scheme: dark) {
    body { background: #17171a; color: #f2f3f5; }
  }
  form {
    width: min(22rem, calc(100vw - 2rem)); padding: 2rem;
    background: #fff; border-radius: 12px;
    box-shadow: 0 1px 3px rgb(0 0 0 / .1), 0 8px 24px rgb(0 0 0 / .06);
  }
  @media (prefers-color-scheme: dark) {
    form { background: #232326; box-shadow: 0 1px 3px rgb(0 0 0 / .4); }
  }
  h1 { margin: 0 0 1.5rem; font-size: 1.125rem; font-weight: 600; }
  input {
    width: 100%; padding: .625rem .75rem; font-size: 1rem;
    border: 1px solid #c9cdd4; border-radius: 8px;
    background: transparent; color: inherit;
  }
  input:focus { outline: 2px solid #4e6ef2; outline-offset: -1px; border-color: #4e6ef2; }
  button {
    width: 100%; margin-top: 1rem; padding: .625rem 1rem;
    font-size: 1rem; font-weight: 500; color: #fff; cursor: pointer;
    background: #4e6ef2; border: 0; border-radius: 8px;
  }
  button:hover { background: #405bd8; }
  p { margin: 0 0 1rem; font-size: .875rem; color: #e34d59; }
</style>
</head>
<body>
  <form method="post" action="${LOGIN_PATH}">
    <h1>请输入密码</h1>
    ${message ? `<p>${escapeHtml(message)}</p>` : ""}
    <input type="password" name="password" placeholder="密码" autofocus required>
    <input type="hidden" name="next" value="${escapeHtml(next)}">
    <button type="submit">进入</button>
  </form>
</body>
</html>`;

  return new Response(html, {
    status: message ? 401 : 200,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

/**
 * Decide whether a request is already authenticated.
 * @param {Request} request Incoming request.
 * @param {{ADMIN_PASSWORD?: string}} env Bound environment variables.
 * @returns {Promise<boolean>} True when the session cookie is valid.
 */
async function isAuthenticated(request, env) {
  const password = env.ADMIN_PASSWORD;
  if (!password) return false;
  return verifySession(readCookie(request, SESSION_COOKIE), password);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS headers
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers":
        "Content-Type, Authorization, X-Requested-With",
    };

    // Handle OPTIONS request
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // The login route must stay reachable before a session exists.
    if (url.pathname === LOGIN_PATH) {
      if (request.method !== "POST") {
        return loginPage();
      }

      const password = env.ADMIN_PASSWORD;
      if (!password) {
        return new Response("ADMIN_PASSWORD is not configured", {
          status: 500,
          headers: { "Content-Type": "text/plain; charset=utf-8" },
        });
      }

      const form = await request.formData();
      const submitted = String(form.get("password") ?? "");
      const next = String(form.get("next") ?? "/");

      // Only same-site relative targets are honoured, so the login page
      // cannot be used as an open redirect. A control character or a quote
      // anywhere in the value disqualifies it, since it would otherwise end
      // up inside an HTML attribute.
      const safeNext =
        next.startsWith("/") &&
        !next.startsWith("//") &&
        !/["'<>&\r\n\t]/.test(next)
          ? next
          : "/";

      if (!timingSafeEqual(submitted, password)) {
        return loginPage({ message: "密码错误", next: safeNext });
      }

      return new Response(null, {
        status: 303,
        headers: {
          Location: safeNext,
          "Set-Cookie":
            `${SESSION_COOKIE}=${await signSession(password)}; ` +
            `Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}`,
        },
      });
    }

    // Gate every route except the login proxies, which the frontend must reach
    // without credentials to run QR-code and SMS login.
    if (!url.pathname.startsWith("/api/")) {
      // Without ADMIN_PASSWORD nothing can ever authenticate, so say so
      // instead of looping on a login page that cannot succeed.
      if (!env.ADMIN_PASSWORD) {
        return new Response("ADMIN_PASSWORD is not configured", {
          status: 500,
          headers: { "Content-Type": "text/plain; charset=utf-8" },
        });
      }
      if (!(await isAuthenticated(request, env))) {
        return loginPage();
      }
    }

    // Proxy configuration
    const proxies = [
      {
        prefix: "/api/hortor-ucenter",
        target: "https://comb-platform.hortorgames.com",
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Linux; Android 12; ALN-AL80 Build/HUAWEIALN-AL80; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/114.0.5735.196 Mobile Safari/537.36",
          Accept: "application/json",
          Host: "ucenter-app-server.hortorgames.com",
          "Content-Type": "application/json; charset=utf-8",
        },
      },
      {
        prefix: "/api/weixin-long",
        target: "https://long.open.weixin.qq.com",
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Linux; Android 7.0; Mi-4c Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/53.0.2785.49 Mobile MQQBrowser/6.2 TBS/043632 Safari/537.36 MicroMessenger/6.6.1.1220(0x26060135) NetType/WIFI Language/zh_CN",
          Accept: "*/*",
          Referer: "https://open.weixin.qq.com/",
        },
      },
      {
        prefix: "/api/weixin",
        target: "https://open.weixin.qq.com",
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Linux; Android 7.0; Mi-4c Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/53.0.2785.49 Mobile MQQBrowser/6.2 TBS/043632 Safari/537.36 MicroMessenger/6.6.1.1220(0x26060135) NetType/WIFI Language/zh_CN",
          Accept:
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
          Referer: "https://open.weixin.qq.com/",
        },
      },
      {
        prefix: "/api/hortor",
        target: "https://comb-platform.hortorgames.com",
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Linux; Android 12; 23117RK66C Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/95.0.4638.74 Mobile Safari/537.36",
          Accept: "*/*",
          Host: "comb-platform.hortorgames.com",
          Connection: "keep-alive",
          "Content-Type": "text/plain; charset=utf-8",
          Origin: "https://open.weixin.qq.com",
          Referer: "https://open.weixin.qq.com/",
        },
      },
    ].sort((a, b) => b.prefix.length - a.prefix.length); // Sort by length descending to match longest prefix first

    // Find matching proxy
    const proxy = proxies.find((p) => url.pathname.startsWith(p.prefix));

    if (proxy) {
      // Construct new URL
      const targetUrl = new URL(proxy.target);
      targetUrl.pathname = url.pathname.replace(proxy.prefix, "") || "/";
      targetUrl.search = url.search;

      // Prepare request headers
      const newHeaders = new Headers(request.headers);

      // Override headers based on proxy config
      Object.entries(proxy.headers).forEach(([key, value]) => {
        newHeaders.set(key, value);
      });

      // Special handling for Host header (Cloudflare might override it, but good to set intention)
      if (proxy.headers.Host) {
        newHeaders.set("Host", proxy.headers.Host);
      }

      // Create new request
      const newRequest = new Request(targetUrl.toString(), {
        method: request.method,
        headers: newHeaders,
        body: request.body,
        redirect: "follow",
      });

      try {
        const response = await fetch(newRequest);

        // Re-create response to add CORS headers
        const newResponse = new Response(response.body, response);
        Object.entries(corsHeaders).forEach(([key, value]) => {
          newResponse.headers.set(key, value);
        });

        return newResponse;
      } catch (e) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 500,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    }

    // Serve static assets (Cloudflare Pages)
    // If env.ASSETS is available (e.g. in Cloudflare Pages Functions), use it to fetch static assets
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    // Default response for non-proxy paths
    return new Response("Not Found", { status: 404, headers: corsHeaders });
  },
};
