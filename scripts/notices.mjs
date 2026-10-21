// SPDX-License-Identifier: GPL-3.0-or-later
// Writes the licenses of every package esbuild bundled into plugin/dist, as their licenses require.
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const meta = JSON.parse(readFileSync('plugin/dist/meta.json', 'utf8'));
const packages = new Set();
for (const input of Object.keys(meta.inputs)) {
  const m = input.match(/node_modules\/((?:@[^/]+\/)?[^/]+)/);
  if (m) packages.add(m[1]);
}

const sections = [...packages].sort().map((name) => {
  const dir = join('node_modules', name);
  const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
  const file = readdirSync(dir).find((f) => /^(licen[cs]e|copying)(\.|$)/i.test(f));
  const text = file ? readFileSync(join(dir, file), 'utf8').trim() : `(no license file; package.json says ${pkg.license})`;
  return `${name} ${pkg.version} (${pkg.license})\n${'-'.repeat(60)}\n${text}\n`;
});

writeFileSync('plugin/dist/THIRD_PARTY_NOTICES.txt', `stackwatch bundles the following packages into stackwatch.mjs.\n\n${sections.join('\n\n')}`);
console.log(`notices for ${packages.size} packages`);
