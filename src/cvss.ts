// SPDX-License-Identifier: GPL-3.0-or-later
import type { Level } from './types.ts';

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

/** CVSS v3.x base score from its vector, per the FIRST specification. Null when the vector is not v3. */
export function cvss3Score(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const m: Record<string, string> = Object.fromEntries(vector.split('/').slice(1).map((p) => p.split(':') as [string, string]));
  const changed = m.S === 'C';
  const pr = ({ N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 } as Record<string, number>)[m.PR ?? ''];
  const [av, ac, ui, c, i, a] = [AV[m.AV ?? ''], AC[m.AC ?? ''], UI[m.UI ?? ''], CIA[m.C ?? ''], CIA[m.I ?? ''], CIA[m.A ?? '']];
  if ([pr, av, ac, ui, c, i, a].some((v) => v === undefined) || (m.S !== 'U' && m.S !== 'C')) return null;

  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  return roundUp(Math.min(changed ? 1.08 * (impact + exploitability) : impact + exploitability, 10));
}

/** The specification's Roundup: the smallest one-decimal number not below x, free of float noise. */
function roundUp(x: number): number {
  const n = Math.round(x * 100000);
  return n % 10000 === 0 ? n / 100000 : (Math.floor(n / 10000) + 1) / 10;
}

export function levelFromScore(score: number): Level {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

/** GitHub's reviewed labels, as OSV carries them in database_specific.severity. */
export function levelFromLabel(label: string | undefined): Level | null {
  switch ((label ?? '').toUpperCase()) {
    case 'CRITICAL': return 'critical';
    case 'HIGH': return 'high';
    case 'MODERATE':
    case 'MEDIUM': return 'medium';
    case 'LOW': return 'low';
    default: return null;
  }
}
