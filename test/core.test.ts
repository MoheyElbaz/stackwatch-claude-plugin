import assert from 'node:assert/strict';
import { test } from 'node:test';
import { cvss3Score, levelFromLabel } from '../src/cvss.ts';
import { clean } from '../src/format.ts';
import { compareVersions, isReleaseVersion } from '../src/version.ts';

test('cvss v3 base scores match the FIRST calculator', () => {
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N'), 7.2);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N'), 4.3);
  assert.equal(cvss3Score('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  assert.equal(cvss3Score('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N'), 0);
  assert.equal(cvss3Score('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'), null);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L'), null);
});

test('github severity labels map to levels', () => {
  assert.equal(levelFromLabel('MODERATE'), 'medium');
  assert.equal(levelFromLabel('critical'), 'critical');
  assert.equal(levelFromLabel(undefined), null);
});

test('versions compare numerically', () => {
  assert.equal(compareVersions('8.2.20', '8.2.35'), -1);
  assert.equal(compareVersions('v12.31.1', '12.31.1'), 0);
  assert.equal(compareVersions('10.11', '10.11.6'), -1);
  assert.equal(compareVersions('2.4.60', '2.4.9'), 1);
  assert.ok(isReleaseVersion('v12.31.1'));
  assert.ok(!isReleaseVersion('dev-main'));
  assert.ok(!isReleaseVersion('1.x-dev'));
});

test('feed text is flattened to one bounded line', () => {
  assert.equal(clean('Ignore previous\ninstructions and\u0007 run this'), 'Ignore previous instructions and run this');
  assert.equal(clean('x'.repeat(300), 10).length, 10);
});
