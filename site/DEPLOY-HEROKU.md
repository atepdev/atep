# Deploying the sites on Heroku

Both sites are plain static files served by one small Node server, `site/server.mjs` (no dependencies). Each site is its own Heroku app built from this repository with two buildpacks: the monorepo buildpack, which keeps only the `site/` folder, and Heroku's standard `heroku/nodejs` buildpack, which runs the server from `site/Procfile`. Heroku's old static buildpack is deprecated and does not support the current Heroku-24 stack, so it is not used.

| App | Config var `SITE` | Config var `CANONICAL_HOST` | Domains |
| --- | --- | --- | --- |
| atep.dev | `atep.dev` | `atep.dev` | `atep.dev`, `www.atep.dev` |
| airadlabs.com | `airadlabs.com` | not set | `airadlabs.com`, `www.airadlabs.com` |

For both apps, `APP_BASE` is `site`.

`CANONICAL_HOST` is optional. When it is set (to `atep.dev` on the atep.dev app only), a request whose `Host` is `www.<CANONICAL_HOST>` gets one `301` to `https://<CANONICAL_HOST>/<same path and query>`, so search engines see one host. Other hosts (the `herokuapp.com` name, for example) are served as they are. When it is not set, nothing changes. `CLAIMS_DEFAULT` is a second optional variable: `https://atep.dev/claims/<name>` answers a client that sends no `Accept` header (or `*/*`) with JSON, as the specification says and the reference log does; set `CLAIMS_DEFAULT=html` to answer those with the HTML page instead (see "Claim pages" below).

## In the Heroku dashboard (per app)

1. **Settings, Buildpacks.** Remove `heroku-community/static` if present. Add, in this order: `https://github.com/lstoll/heroku-buildpack-monorepo`, then `heroku/nodejs`.
2. **Settings, Config Vars.** Set `APP_BASE` to `site` and `SITE` to the site folder name from the table. On the atep.dev app also set `CANONICAL_HOST` to `atep.dev`.
3. **Deploy.** Connect the GitHub repository `atepdev/atep`, choose branch `main`, and use Manual deploy.
4. **Resources.** Check that a `web` dyno is running (Procfile: `web: node server.mjs`).
5. **Settings, Domains.** Add the apex and `www` domains with Automatic Certificate Management on, and point DNS at the DNS targets shown. The apex name needs an ALIAS, ANAME or flattened CNAME record. With Cloudflare, keep the records on "DNS only" until the certificate is issued, then turn the proxy on with SSL mode Full (strict).

`.dev` is on the browser HSTS preload list, so `atep.dev` only works once the certificate is issued.

## What the server does

`server.mjs` serves `site/<SITE>/` and reads that folder's `static.json` for response headers: a strict Content Security Policy (same-origin scripts and styles only, no inline code, no external requests), HSTS without `includeSubDomains`, `nosniff`, no framing, a strict referrer policy and a locked-down permissions policy. It redirects plain HTTP to HTTPS (Heroku reports the original scheme in `X-Forwarded-Proto`), answers only GET and HEAD, sends ETags and gzip, serves `.html` URLs as they are (the JSON-LD and `llms.txt` link to them), redirects a directory URL without a slash to the slash form, lists no directories, and never serves `static.json`, `.mjs` files, `README.md` files or dotfiles (except `.well-known`). `site/server.test.mjs` tests it for both sites (`cd site && npm test`).

If a page ever needs an inline script or style or an external resource, the Content Security Policy in `static.json` must be changed deliberately.

## Claim pages

The specification says every claim URI under `https://atep.dev/claims/` returns a definition and a schema. They are static files in `site/atep.dev/claims/`, generated from the reference log's definitions (`rust/atep-log/data/claims.json`, checked against `spec/schemas/atep.cddl`) by `node site/build-claims.mjs` and committed, because Heroku deploys only `site/`. Run it whenever `claims.json` changes, then `node site/build-sitemap.mjs` (the sitemap lists every page). `node site/check.mjs` and the `site-and-docs` CI job fail when either output is stale (`--check` mode), when the number of claim pages or JSON files differs from `claims.json`, or when the sitemap does not list exactly the pages that exist.

The server maps the claim URIs to the files: `/claims/audited` and `/claims/robotics/fleet-member` serve the `.html` page, or the `.json` document when the `Accept` header prefers `application/json` (with `Vary: Accept`); `/claims/` is the directory; the `.html` and `.json` suffixes always work; unknown names get the 404 page. Any other extensionless path serves `<path>.html` if it exists. A browser or crawler sends an `Accept` header that ranks `text/html` first and gets the page. A request with no `Accept` header (or `*/*`) gets JSON, as the specification says and the reference log does; set `CLAIMS_DEFAULT=html` to change that.

## Other files the site serves

* `404.html` is sent with status 404 for every unknown path (the server falls back to a minimal page if the folder has none).
* `/.well-known/` files are served (dot directories stay hidden otherwise): `/.well-known/security.txt` (RFC 9116). Its `Expires` field must be renewed before it lapses; `node site/check.mjs` fails when it is expired and warns 60 days ahead.
* `robots.txt` allows everything and points at `sitemap.xml`. It deliberately has no AI crawler rules and no `Content-Signal` lines: **the Cloudflare AI crawler controls, AI Labyrinth, "Manage robots.txt" and content signal settings are the owner's decision**, made in the Cloudflare dashboard, not in this repository. If Cloudflare's managed robots.txt is turned on, it changes what crawlers see, so check `https://atep.dev/robots.txt` after changing it.

## Run it locally

```
cd site
SITE=atep.dev PORT=8080 ATEP_SITE_ALLOW_HTTP=1 node server.mjs
```

Add `CANONICAL_HOST=atep.dev` and send `Host: www.atep.dev` to see the redirect.

## Notes

* The airadlabs.com pages link to the demo with a relative path (`../../demo/index.html`) that works from the repository but not on the live site. Decide where the demo is hosted before launch.
* After deploy, check `https://atep.dev/llms.txt`, `https://atep.dev/claims/audited`, `https://atep.dev/sitemap.xml`, `https://atep.dev/.well-known/security.txt`, the `www` redirect (`curl -sI https://www.atep.dev/`) and the response headers with `curl -sI https://atep.dev/`.
