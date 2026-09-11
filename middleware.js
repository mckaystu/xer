/**
 * HTTP Basic Auth for static CDN assets on Vercel.
 * FastAPI BasicAuthMiddleware still guards /api/* (defense in depth).
 * Leave XER_APP_PASSWORD unset to disable.
 */
import { next } from "@vercel/functions";

export const config = {
  matcher: ["/((?!api/health).*)"],
};

export default function middleware(request) {
  const password = (process.env.XER_APP_PASSWORD || "").trim();
  if (!password) {
    return next();
  }

  const username = (process.env.XER_APP_USERNAME || "xer").trim() || "xer";
  const auth = request.headers.get("authorization") || "";
  if (auth.toLowerCase().startsWith("basic ")) {
    try {
      const raw = atob(auth.slice(6).trim());
      const i = raw.indexOf(":");
      if (i >= 0) {
        const user = raw.slice(0, i);
        const pwd = raw.slice(i + 1);
        if (user === username && pwd === password) {
          return next();
        }
      }
    } catch (_) {
      // fall through to 401
    }
  }

  return new Response("Authentication required", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="Xer", charset="UTF-8"',
      "Content-Type": "text/plain",
    },
  });
}
