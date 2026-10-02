# Deploying the sites on Heroku

Each site in this folder is plain static files and deploys as its own Heroku app from this repository, using two buildpacks: the monorepo buildpack (keeps only the site's folder) and the static buildpack (serves it with nginx, configured by that folder's `static.json`).

| App | `APP_BASE` | Domains |
| --- | --- | --- |
| atep.dev | `site/atep.dev` | `atep.dev`, `www.atep.dev` |
| airadlabs.com | `site/airadlabs.com` | `airadlabs.com`, `www.airadlabs.com` |

Replace `<app>` with your Heroku app name. The buildpack names below are from memory of Heroku's documentation; confirm them there before the first deploy.

```
heroku create <app>
heroku buildpacks:add https://github.com/lstoll/heroku-buildpack-monorepo
heroku buildpacks:add heroku-community/static
heroku config:set APP_BASE=site/atep.dev          # or site/airadlabs.com
git push heroku main                               # or connect the GitHub repo and enable automatic deploys after CI passes
```

Order matters: the monorepo buildpack must come first.

## Domains and the certificate

```
heroku domains:add atep.dev -a <app>
heroku domains:add www.atep.dev -a <app>
heroku certs:auto:enable -a <app>
heroku domains -a <app>                            # shows the DNS target for each domain
```

At the DNS provider, point `www` at its DNS target with a CNAME. The apex name (`atep.dev`) needs an ALIAS, ANAME or CNAME-flattening record at the provider, pointing at the apex's DNS target; a plain CNAME is not allowed at the apex. Heroku issues the HTTPS certificate automatically once DNS resolves (`heroku certs:auto -a <app>` shows progress). Custom domains need a paid dyno type; the cheapest one is enough for a static site.

`.dev` is on the browser HSTS preload list: browsers refuse plain HTTP for `atep.dev`, so the site only works once the certificate is issued.

## What `static.json` sets

HTTPS only, URLs keep their `.html` names (the JSON-LD and the `llms.txt` links use them), and security headers: a strict Content Security Policy (same-origin scripts and styles only, no inline code, no external requests), HSTS without `includeSubDomains` (so other subdomains you run are not forced to HTTPS by this site), `nosniff`, no framing, a strict referrer policy and a locked-down permissions policy. If a page ever needs an inline script or style or an external resource, the Content Security Policy must be changed deliberately.

## Notes

* The airadlabs.com pages link to the demo with a relative path (`../../demo/index.html`) that works from the repository but not on the live site. Decide where the demo is hosted (a third app serving `demo/`, or a sub-path) before launch.
* `https://atep.dev/claims/<name>` is named in the specification as a resolvable claim URI. It can be served by generating static files from the claim definitions (a later step) or by proxying to a log.
* After deploy, check `https://atep.dev/llms.txt`, `https://atep.dev/llms-full.txt` and the response headers with `curl -sI https://atep.dev/`.
