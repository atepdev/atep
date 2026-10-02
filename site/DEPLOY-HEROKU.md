# Deploying the sites on Heroku

Both sites are plain static files served by one small Node server, `site/server.mjs` (no dependencies). Each site is its own Heroku app built from this repository with two buildpacks: the monorepo buildpack, which keeps only the `site/` folder, and Heroku's standard `heroku/nodejs` buildpack, which runs the server from `site/Procfile`. Heroku's old static buildpack is deprecated and does not support the current Heroku-24 stack, so it is not used.

| App | Config var `SITE` | Domains |
| --- | --- | --- |
| atep.dev | `atep.dev` | `atep.dev`, `www.atep.dev` |
| airadlabs.com | `airadlabs.com` | `airadlabs.com`, `www.airadlabs.com` |

For both apps, `APP_BASE` is `site`.

## In the Heroku dashboard (per app)

1. **Settings, Buildpacks.** Remove `heroku-community/static` if present. Add, in this order: `https://github.com/lstoll/heroku-buildpack-monorepo`, then `heroku/nodejs`.
2. **Settings, Config Vars.** Set `APP_BASE` to `site` and `SITE` to the site folder name from the table.
3. **Deploy.** Connect the GitHub repository `atepdev/atep`, choose branch `main`, and use Manual deploy.
4. **Resources.** Check that a `web` dyno is running (Procfile: `web: node server.mjs`).
5. **Settings, Domains.** Add the apex and `www` domains with Automatic Certificate Management on, and point DNS at the DNS targets shown. The apex name needs an ALIAS, ANAME or flattened CNAME record. With Cloudflare, keep the records on "DNS only" until the certificate is issued, then turn the proxy on with SSL mode Full (strict).

`.dev` is on the browser HSTS preload list, so `atep.dev` only works once the certificate is issued.

## What the server does

`server.mjs` serves `site/<SITE>/` and reads that folder's `static.json` for response headers: a strict Content Security Policy (same-origin scripts and styles only, no inline code, no external requests), HSTS without `includeSubDomains`, `nosniff`, no framing, a strict referrer policy and a locked-down permissions policy. It redirects plain HTTP to HTTPS (Heroku reports the original scheme in `X-Forwarded-Proto`), answers only GET and HEAD, sends ETags and gzip, serves `.html` URLs as they are (the JSON-LD and `llms.txt` link to them), and never serves `static.json`, `.mjs` files, `README.md` files or dotfiles. `site/server.test.mjs` tests it for both sites (`cd site && npm test`).

If a page ever needs an inline script or style or an external resource, the Content Security Policy in `static.json` must be changed deliberately.

## Run it locally

```
cd site
SITE=atep.dev PORT=8080 ATEP_SITE_ALLOW_HTTP=1 node server.mjs
```

## Notes

* The airadlabs.com pages link to the demo with a relative path (`../../demo/index.html`) that works from the repository but not on the live site. Decide where the demo is hosted before launch.
* `https://atep.dev/claims/<name>` is named in the specification as a resolvable claim URI. It can be served by generating static files from the claim definitions (a later step) or by proxying to a log.
* After deploy, check `https://atep.dev/llms.txt`, `https://atep.dev/llms-full.txt` and the response headers with `curl -sI https://atep.dev/`.
