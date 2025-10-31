const join = (...parts) => parts.join('/').replace(/\/{2,}/g, '/').replace(':/', '://');

export function createApi({ baseUrl, token }) {
  const root = baseUrl.replace(/\/+$/,'');
  const headers = () => ({
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {})
  });

  const j = async (r) => {
    if (!r.ok) {
      let msg = `HTTP ${r.status}`;
      try { const b = await r.json(); msg = b?.message || msg; } catch {}
      throw new Error(msg);
    }
    return r.json();
  };

  return {
    // Ideas
    createIdea: (payload, { email } = {}) =>
      fetch(join(root, '/ideas') + (email ? `?email=${encodeURIComponent(email)}` : ''), {
        method: 'POST', headers: headers(), body: JSON.stringify(payload)
      }).then(j),

    updateIdea: (id, patch, { email } = {}) =>
      fetch(join(root, `/ideas/${id}`) + (email ? `?email=${encodeURIComponent(email)}` : ''), {
        method: 'PATCH', headers: headers(), body: JSON.stringify(patch)
      }).then(j),

    deleteIdea: (id) =>
      fetch(join(root, `/ideas/${id}`), { method: 'DELETE', headers: headers() }).then(j),

    getIdea: (id) =>
      fetch(join(root, `/ideas/${id}`), { headers: headers() }).then(j),

    latestIdeas: (limit = 30) =>
      fetch(join(root, `/ideas/latest?limit=${limit}`), { headers: headers() }).then(j),

    // Likes
    like:   (id, { userId, displayName }) =>
      fetch(join(root, `/ideas/${id}/likes`), { method: 'POST', headers: headers(),
        body: JSON.stringify({ action:'like', userId, displayName }) }).then(j),
    unlike: (id, { userId }) =>
      fetch(join(root, `/ideas/${id}/likes`), { method: 'POST', headers: headers(),
        body: JSON.stringify({ action:'unlike', userId }) }).then(j),
    toggleLike: (id, { userId, displayName }) =>
      fetch(join(root, `/ideas/${id}/likes/toggle`), { method: 'POST', headers: headers(),
        body: JSON.stringify({ action:'toggle', userId, displayName }) }).then(j),

    // Comments
    addComment: (id, { text, authorId, authorName }) =>
      fetch(join(root, `/ideas/${id}/comments`), { method: 'POST', headers: headers(),
        body: JSON.stringify({ text, authorId, authorName }) }).then(j),
    editComment: (id, cid, { text }) =>
      fetch(join(root, `/ideas/${id}/comments/${cid}`), { method: 'PATCH', headers: headers(),
        body: JSON.stringify({ text }) }).then(j),
    deleteComment: (id, cid) =>
      fetch(join(root, `/ideas/${id}/comments/${cid}`), { method: 'DELETE', headers: headers() }).then(j),

    // Drawings
    setDrawings: (id, items) =>
      fetch(join(root, `/ideas/${id}/drawings`), { method: 'POST', headers: headers(),
        body: JSON.stringify({ items }) }).then(j),

    // Chart image (multipart file)
    uploadChartFile: async (id, file) => {
      const fd = new FormData();
      fd.append('file', file);
      const h = token ? { 'Authorization': `Bearer ${token}` } : {};
      const r = await fetch(join(root, `/ideas/${id}/chart`), { method: 'POST', headers: h, body: fd });
      return j(r);
    },

    // Chart image (data URL)
    uploadChartDataUrl: (id, dataUrl) =>
      fetch(join(root, `/ideas/${id}/chart`), { method: 'POST', headers: headers(),
        body: JSON.stringify({ dataUrl }) }).then(j),

    // Chart via external URL (stored directly as URL)
    setChartUrl: (id, url) =>
      fetch(join(root, `/ideas/${id}/chart/url`), { method: 'POST', headers: headers(),
        body: JSON.stringify({ url }) }).then(j),

    // Fetch remote chart and save locally
    fetchChartToUploads: (id, { url, referer, userAgent }) =>
      fetch(join(root, `/ideas/${id}/chart/fetch`), { method: 'POST', headers: headers(),
        body: JSON.stringify({ url, referer, userAgent }) }).then(j),

    // Email
    emailPost: (itemOrId) => {
      if (typeof itemOrId === 'string') {
        return fetch(join(root, `/email/idea/${itemOrId}`), { method:'POST', headers: headers(),
          body: JSON.stringify({ type:'post' }) }).then(j);
      }
      return fetch(join(root, `/email/post`), { method:'POST', headers: headers(),
        body: JSON.stringify({ item: itemOrId }) }).then(j);
    },
    emailSignal: (itemOrId) => {
      if (typeof itemOrId === 'string') {
        return fetch(join(root, `/email/idea/${itemOrId}`), { method:'POST', headers: headers(),
          body: JSON.stringify({ type:'signal' }) }).then(j);
      }
      return fetch(join(root, `/email/signal`), { method:'POST', headers: headers(),
        body: JSON.stringify({ item: itemOrId }) }).then(j);
    },

    // Subscribers
    subscribe: ({ email, name }) =>
      fetch(join(root, `/subscribe`), { method:'POST', headers: headers(),
        body: JSON.stringify({ email, name }) }).then(j),
    unsubscribe: ({ email }) =>
      fetch(join(root, `/unsubscribe`), { method:'POST', headers: headers(),
        body: JSON.stringify({ email }) }).then(j),

    // Public (if enabled on server)
    publicSubscribe: ({ email, name }) =>
      fetch(join(root, `/public/subscribe`), { method:'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, name }) }).then(j),
    publicUnsubscribe: ({ email }) =>
      fetch(join(root, `/public/unsubscribe`), { method:'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }) }).then(j),

    // Debug email
    debugEmailStatus: () =>
      fetch(join(root, `/debug/email/status`), { headers: headers() }).then(j),
    debugEmailTest: ({ to, img }) =>
      fetch(join(root, `/debug/email/test`), { method:'POST', headers: headers(),
        body: JSON.stringify({ to, img }) }).then(j),
  };
}
