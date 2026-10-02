// Derives the public brand assets from the private original. Usage (see README.md):
//   node build-assets.mjs /path/to/atep-logo-original.jpg
// Requires `sharp` (install it outside the repo and set NODE_PATH, see README.md).
import sharp from "sharp";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const src = process.argv[2];
if (!src) { console.error("usage: node build-assets.mjs <atep-logo-original.jpg>"); process.exit(2); }

// 1. Wordmark: tight crop (letters span x 189..980, y 772..952) with padding, original background kept.
const crop = { left: 100, top: 692, width: 970, height: 340 };
const wordmark = await sharp(src).extract(crop).jpeg({ quality: 82, mozjpeg: true }).toBuffer();
fs.writeFileSync(path.join(here, "atep-wordmark.jpg"), wordmark);

// 2. Favicons from favicon.svg (a vector redraw of the A glyph).
const svg = fs.readFileSync(path.join(here, "favicon.svg"));
await sharp(svg, { density: 600 }).resize(32, 32).png({ compressionLevel: 9 }).toFile(path.join(here, "favicon-32.png"));
await sharp(svg, { density: 600 }).resize(180, 180).png({ compressionLevel: 9 }).toFile(path.join(here, "apple-touch-icon.png"));

// 3. Social card 1200x630: wordmark centred, one-line description below.
const wm0 = await sharp(wordmark).resize({ width: 760 }).toBuffer();
const wmH = (await sharp(wm0).metadata()).height;
// Feather the edges so the JPEG background blends into the card instead of showing a box.
const mask = Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="760" height="${wmH}"><defs><filter id="f" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="22"/></filter></defs><rect x="48" y="48" width="${760 - 96}" height="${wmH - 96}" fill="#fff" filter="url(#f)"/></svg>`);
const wm = await sharp(wm0).ensureAlpha().composite([{ input: await sharp(mask).png().toBuffer(), blend: "dest-in" }]).png().toBuffer();
const text = "Quantum-safe trust layer for robots and AI agents. Verifies offline.";
const base = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630">
<defs><radialGradient id="v" cx="50%" cy="45%" r="75%"><stop offset="0" stop-color="#101114"/><stop offset="1" stop-color="#050506"/></radialGradient></defs>
<rect width="1200" height="630" fill="url(#v)"/>
<text x="600" y="500" text-anchor="middle" font-family="DejaVu Sans, Liberation Sans, Arial, Helvetica, sans-serif" font-size="30" fill="#c9cbd2">${text}</text>
<rect x="540" y="450" width="120" height="3" fill="#17b5f1"/>
</svg>`;
await sharp(Buffer.from(base)).composite([{ input: wm, left: 220, top: Math.round(215 - wmH / 2) }]).jpeg({ quality: 86, mozjpeg: true }).toFile(path.join(here, "og-card.jpg"));
