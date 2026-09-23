#!/usr/bin/env node
// Mirrors the repo root's docs/trusted-networks.json into
// src/generated/trustedNetworks.json so src/network/trustAnchors.ts can
// import it as a plain, in-src JSON module (resolveJsonModule) without
// reaching outside this package's own TypeScript project or hand-copying
// the file. Same approach generate-types.mjs already uses for
// src/generated.ts, and the same one apps/hub/src/network/trustAnchors.ts
// gets from vite.config.ts's dev/build-time mirror.
import { copyFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

const SOURCE_PATH = fileURLToPath(
  new URL("../../../docs/trusted-networks.json", import.meta.url),
);
const OUT_DIR = fileURLToPath(new URL("../src/generated", import.meta.url));
const OUT_PATH = fileURLToPath(
  new URL("../src/generated/trustedNetworks.json", import.meta.url),
);

mkdirSync(OUT_DIR, { recursive: true });
copyFileSync(SOURCE_PATH, OUT_PATH);
