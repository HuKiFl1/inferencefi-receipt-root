import { writeFileSync } from "node:fs";
import { serializeVectors } from "./vectors.js";

const path = new URL("../vectors/receipt-root-v1.json", import.meta.url);
writeFileSync(path, serializeVectors());
process.stdout.write(`wrote ${path.pathname}\n`);
