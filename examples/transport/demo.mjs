import { init } from "../common/atep.mjs";
import { runSameBytes } from "./same-bytes.mjs";
await init();
const { hops } = await runSameBytes();
for (const h of hops) console.log(h.hop.padEnd(8), h.sha256, h.verification ? (h.verification.ok ? "verified" : `REJECTED ${h.verification.step}`) : "");
