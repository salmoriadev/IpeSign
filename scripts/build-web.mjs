import { copyFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const assets = resolve(root, "apps/web/public/assets");

await mkdir(assets, { recursive: true });
await Promise.all([
  copyFile(resolve(root, "node_modules/pdf-lib/dist/pdf-lib.min.js"), resolve(assets, "pdf-lib.min.js")),
  copyFile(resolve(root, "node_modules/pdfjs-dist/build/pdf.min.mjs"), resolve(assets, "pdf.min.mjs")),
  copyFile(resolve(root, "node_modules/pdfjs-dist/build/pdf.worker.min.mjs"), resolve(assets, "pdf.worker.min.mjs"))
]);
