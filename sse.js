export function connectIdeasSSE({ baseUrl, token, on }) {
  const src = new EventSource(`${baseUrl.replace(/\/+$/,'')}/events${token ? `?token=${encodeURIComponent(token)}` : ''}`);

  function bind(event, cb) {
    if (!cb) return;
    src.addEventListener(event, (ev) => {
      try { cb(JSON.parse(ev.data)); } catch { cb(ev.data); }
    });
  }

  bind('hello', on?.hello);
  bind('idea:new', on?.ideaNew);
  bind('idea:update', on?.ideaUpdate);
  bind('idea:delete', on?.ideaDelete);
  bind('comments:update', on?.commentsUpdate);
  bind('likes:update', on?.likesUpdate);
  bind('drawings:update', on?.drawingsUpdate);

  src.onerror = (e) => on?.error?.(e);
  return () => src.close();
}
