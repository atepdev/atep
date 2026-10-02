# Brand assets

Derived from the private original logo (1152x1728 JPEG, kept in the private archive and not committed). Files here:

| File | What | Source |
| --- | --- | --- |
| `atep-wordmark.jpg` | 970x340 crop around the letters, original dark background kept (header and README banner) | crop of the original |
| `favicon.svg` | hand drawn vector of the A glyph (silver chevron, blue stripe, near-black rounded square) | traced from the original, edited by hand |
| `favicon-32.png`, `apple-touch-icon.png` | 32 px and 180 px renders of `favicon.svg` | `build-assets.mjs` |
| `og-card.jpg` | 1200x630 social card: wordmark plus the one-line description | `build-assets.mjs` |

Regenerate (needs Node 18 or later and the `sharp` npm package, installed outside the repository):

```
mkdir -p /tmp/sharp-scratch && cd /tmp/sharp-scratch && npm init -y && npm i sharp
NODE_PATH=/tmp/sharp-scratch/node_modules node site/atep.dev/assets/build-assets.mjs /path/to/atep-logo-original.jpg
```

`sharp` is an ES module import here, so copy the script next to the scratch `node_modules` if your Node does not honor `NODE_PATH` for ES modules.

Colour tokens sampled from the original: background `#0c0d0f`, silver `#e7e5ea`, blue `#17b5f1` (mean of the blue pixels; the A stripe is `#04adf9`).

The ATEP name and logo are not covered by the repository licenses; see the README.
