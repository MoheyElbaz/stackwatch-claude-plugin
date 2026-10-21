// SPDX-License-Identifier: GPL-3.0-or-later
/** Compares dotted numeric versions ("8.3.20" < "8.3.36"); a leading "v" and suffixes are ignored. */
export function compareVersions(a: string, b: string): number {
  const parts = (v: string) => v.replace(/^v/, '').split(/[.+-]/).map((p) => Number.parseInt(p, 10));
  const x = parts(a);
  const y = parts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = Number.isNaN(x[i]) ? 0 : (x[i] ?? 0);
    const q = Number.isNaN(y[i]) ? 0 : (y[i] ?? 0);
    if (p !== q) return p < q ? -1 : 1;
  }
  return 0;
}

/** "8.3.20" -> "8.3" */
export function branchOf(version: string): string {
  return version.replace(/^v/, '').split('.').slice(0, 2).join('.');
}

/** A version OSV can match: starts with a digit, optionally after "v". Not "dev-main". */
export function isReleaseVersion(version: string): boolean {
  return /^v?\d/.test(version) && !/-dev$|^dev-/.test(version);
}
