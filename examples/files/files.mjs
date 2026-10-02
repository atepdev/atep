// Envelope bytes as a file on disk. Nothing ATEP specific: the file IS the envelope.
import { writeFile, readFile } from "node:fs/promises";

export const FILE_EXTENSION = ".atep"; // convention of these examples, not a registered extension

export const writeEnvelopeFile = (path, bytes) => writeFile(path, bytes);
export async function readEnvelopeFile(path) {
  return new Uint8Array(await readFile(path));
}
