import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { serializeVectors } from "./vectors.js";

const out = join(dirname(fileURLToPath(import.meta.url)), "..", "vectors", "if-d8-v2.json");
writeFileSync(out, serializeVectors());
console.log(`wrote ${out}`);
