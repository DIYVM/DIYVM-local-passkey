import { cp, mkdir, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outputDirectory = resolve(packageRoot, "dist");
const isStoreBuild = process.argv.includes("--store");

await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });

await build({
  absWorkingDir: packageRoot,
  entryPoints: {
    background: "src/background.ts",
    popup: "src/popup.ts",
    confirmation: "src/confirmation.ts",
    "page-bridge": "src/page-bridge.ts",
    "content-script": "src/content-script.ts",
    "password-autofill": "src/password-autofill.ts"
  },
  bundle: true,
  format: "esm",
  outdir: outputDirectory,
  platform: "browser",
  target: "chrome120",
  sourcemap: !isStoreBuild,
  logLevel: "info"
});

await Promise.all(
  [
    "manifest.json",
    "src/popup.html",
    "src/popup.css",
    "src/confirmation.html",
    "src/confirmation.css",
    "src/logo.png"
  ].map(async (source) => {
    const fileName = source.split("/").at(-1);
    if (!fileName) {
      throw new Error(`Unable to determine output name for ${source}`);
    }
    await cp(resolve(packageRoot, source), resolve(outputDirectory, fileName));
  })
);

await cp(
  resolve(packageRoot, "icons"),
  resolve(outputDirectory, "icons"),
  { recursive: true }
);
