const CANONICAL_HOSTNAME = "pop.byteray.co.uk";

export default {
  fetch(request) {
    // Rewrite the request URL in place rather than resolving its path against
    // the canonical origin: a path beginning with "//" would resolve to another host.
    const location = new URL(request.url);
    location.protocol = "https:";
    location.hostname = CANONICAL_HOSTNAME;
    location.port = "";

    return new Response(null, {
      status: 301,
      headers: {
        Location: location.href,
        "Cache-Control": "public, max-age=86400",
      },
    });
  },
};
