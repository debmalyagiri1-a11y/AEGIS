
/* =========================================
   AEGIS — AUTHENTICATED API FETCH
   Supports Login, MFA, Dashboard & Scanner
========================================= */

(() => {
  const nativeFetch = window.fetch.bind(window);

  const API_HOST = "aegis-4lcw.onrender.com";

  const PUBLIC_ENDPOINTS = new Set([
    "/login",
    "/register",
    "/verify-mfa",
    "/forgot-password",
    "/reset-password"
  ]);

  window.fetch = function(input, init = {}) {
    let target;

    try {
      const raw =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url;

      target = new URL(raw, location.href);
    } catch (error) {
      return nativeFetch(input, init);
    }

    const isLocal =
      target.hostname === "127.0.0.1" ||
      target.hostname === "localhost";

    const isAPI =
      target.hostname === API_HOST ||
      (isLocal &&
        ["8000", "8001"].includes(target.port));

    if (!isAPI) {
      return nativeFetch(input, init);
    }

    const headers = new Headers(
      input instanceof Request
        ? input.headers
        : undefined
    );

    if (init.headers) {
      new Headers(init.headers).forEach(
        (value, key) => headers.set(key, value)
      );
    }

    const path =
      target.pathname.replace(/\/+$/, "") || "/";

    if (PUBLIC_ENDPOINTS.has(path)) {
      headers.delete("Authorization");
    } else {
      const token =
        sessionStorage.getItem("aegisAccessToken");

      if (token) {
        headers.set(
          "Authorization",
          "Bearer " + token
        );
      }
    }

    return nativeFetch(input, {
      ...init,
      headers
    });
  };
})();
