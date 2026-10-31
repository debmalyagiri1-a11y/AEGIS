/* AEGIS authenticated requests. Load before existing page scripts. */
(() => {
  const nativeFetch = window.fetch.bind(window);
  const API_HOST = 'aegis-4lcw.onrender.com';
  window.fetch = function(input, init = {}) {
    const raw = typeof input === 'string' ? input : input?.url;
    let target;
    try { target = new URL(raw, location.href); } catch (_) { return nativeFetch(input, init); }
    const local = target.hostname === '127.0.0.1' || target.hostname === 'localhost';
    const isApi = target.hostname === API_HOST || (local && target.port === '8000');
    if (!isApi) return nativeFetch(input, init);
    const token = sessionStorage.getItem('aegisAccessToken');
    if (!token) return nativeFetch(input, init);
    const headers = new Headers(init.headers || (input instanceof Request ? input.headers : undefined));
    headers.set('Authorization', 'Bearer ' + token);
    return nativeFetch(input, {...init, headers});
  };
})();
