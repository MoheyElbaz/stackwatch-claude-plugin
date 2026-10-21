// SPDX-License-Identifier: GPL-3.0-or-later
// Bundles src/cli.ts into plugin/dist, committed so installs need no build.
//
// The plugin directory reads each file only up to 256 KiB, so the bundle is split: stackwatch.mjs
// holds the CLI and the session hook and loads the MCP server, zod and ajv from chunks/ only when
// the MCP server starts. Every file is checked against MAX_FILE. Two unused parts of dependencies
// are left out (see scripts/shims): zod's non-English messages and is-unsafe's non-XML pattern lists.
import { build } from 'esbuild';
import { rmSync, writeFileSync } from 'node:fs';
import { resolve, sep } from 'node:path';

const OUT = 'plugin/dist';
const MAX_FILE = 240 * 1024;

const banner = [
  '#!/usr/bin/env node',
  '// stackwatch, GPL-3.0-or-later, https://github.com/MoheyElbaz/stackwatch-claude-plugin (bundled packages and their licenses: THIRD_PARTY_NOTICES.txt)',
  "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);",
].join('\n');

// Entry points that only re-export a package. With splitting on, the modules each one reaches go
// to a chunk of their own instead of one large MCP chunk.
const vendor = { 'chunks/zod-v4': 'zod/v4', 'chunks/zod-v3': 'zod/v3', 'chunks/ajv': 'ajv' };

const plugins = [{
  name: 'stackwatch',
  setup(b) {
    b.onResolve({ filter: /^vendor:/ }, (a) => ({ path: a.path.slice('vendor:'.length), namespace: 'vendor' }));
    b.onLoad({ filter: /.*/, namespace: 'vendor' }, (a) => ({ contents: `export * from ${JSON.stringify(a.path)};`, resolveDir: process.cwd(), loader: 'js' }));
    b.onResolve({ filter: /^is-unsafe$/ }, () => ({ path: resolve('scripts/shims/is-unsafe.mjs') }));
    b.onResolve({ filter: /^\.\.\/locales\/index\.js$/ }, (a) => (a.importer.includes(`${sep}node_modules${sep}zod${sep}v4${sep}`) ? { path: resolve('scripts/shims/zod-locales.mjs') } : undefined));
  },
}];

rmSync(OUT, { recursive: true, force: true });
const result = await build({
  entryPoints: { stackwatch: 'src/cli.ts', ...Object.fromEntries(Object.entries(vendor).map(([out, pkg]) => [out, `vendor:${pkg}`])) },
  bundle: true,
  splitting: true,
  format: 'esm',
  platform: 'node',
  target: 'node20',
  outdir: OUT,
  outExtension: { '.js': '.mjs' },
  chunkNames: 'chunks/[name]-[hash]',
  minify: true,
  legalComments: 'none',
  banner: { js: banner },
  metafile: true,
  plugins,
  logLevel: 'warning',
});

const outputs = Object.entries(result.metafile.outputs).sort((a, b) => b[1].bytes - a[1].bytes);
for (const [file, { bytes }] of outputs) console.log(`${(bytes / 1024).toFixed(1).padStart(7)} KiB  ${file}`);
const tooBig = outputs.filter(([, o]) => o.bytes > MAX_FILE);
if (tooBig.length) {
  console.error(`over ${MAX_FILE / 1024} KiB: ${tooBig.map(([f]) => f).join(', ')}. Add an entry to vendor in scripts/build.mjs.`);
  process.exit(1);
}
writeFileSync(`${OUT}/meta.json`, JSON.stringify(result.metafile));
