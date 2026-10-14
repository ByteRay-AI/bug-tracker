# pop-argus-redirect

Cloudflare Worker that retires `pop.argus-systems.ai`. Every request gets a
`301` to the same path and query on `https://pop.byteray.co.uk`, so advisory
links published with the old domain keep working.

- Route: `pop.argus-systems.ai/*` in the `argus-systems.ai` zone. The existing
  proxied DNS record stays in place; the Worker answers before any origin is
  contacted.
- No bindings or secrets. `workers.dev` and Preview URLs are disabled.
- `Cache-Control: public, max-age=86400` lets browsers reuse the redirect for a
  day.

## Test and deploy

```bash
npm ci
npm test              # unit tests (node:test)
npx wrangler dev      # then: curl -sI 'http://localhost:8787/advisory/adv-038.html?x=1'
npx wrangler deploy   # needs a Wrangler login with access to the argus-systems.ai zone
```

[DEPLOYMENT.md](../../../DEPLOYMENT.md) explains how this fits the site's
hosting.
