import assert from 'node:assert/strict';
import { join } from 'node:path';
import { test } from 'node:test';
import { detect } from '../src/detect.ts';

const project = join(import.meta.dirname, 'fixtures', 'project');

test('lockfiles become components; installed copies and links are not', () => {
  const found = detect(project);
  const names = found.components.map((c) => `${c.ecosystem}:${c.name}@${c.version}${c.dev ? ' dev' : ''}`);

  assert.deepEqual(found.files.sort(), ['.tool-versions', 'Dockerfile', 'composer.lock', 'docker-compose.yml', 'package-lock.json', 'packages/billing/composer.lock']);
  assert.ok(names.includes('Packagist:symfony/http-kernel@v7.1.5'), 'a package listed as both deployed and dev counts as deployed');
  assert.ok(names.includes('Packagist:phpunit/phpunit@11.5.0 dev'));
  assert.ok(names.includes('npm:axios@1.7.0'));
  assert.ok(names.includes('npm:esbuild@0.24.0 dev'), 'nested installs are read by their own name');
  assert.ok(!names.some((n) => n.includes('local-pkg')), 'linked workspace packages are not installs');
  assert.ok(!names.some((n) => n.includes('should/not-appear')), 'vendor/ is never scanned');
  assert.ok(found.hints.some((h) => h.includes('requires PHP ^8.3')));
  assert.ok(!found.hints.some((h) => /composer\.json|package-lock|not read yet/.test(h) && !h.includes('requires')), `ordinary files are not reported: ${found.hints.join(' | ')}`);
});

test('runtimes come from Docker images, compose files and version files', () => {
  const runtimes = detect(project).components.filter((c) => c.product).map((c) => `${c.product} ${c.version}${c.exact === false ? ' (line)' : ''} <- ${c.source}`);
  assert.deepEqual(runtimes.sort(), [
    'mysql 8.0.39 <- docker-compose.yml',
    'nodejs 22.11.0 <- .tool-versions',
    'php 8.2.20 <- Dockerfile',
    'redis 7.2 (line) <- docker-compose.yml',
  ], 'node:22 is dropped for the exact 22.11.0; private images and ${VARS} are ignored');
  assert.ok(detect(project).hints.some((h) => h.includes('uses nginx') && h.includes('pin it')));
});

test('excluded paths are left out', () => {
  const found = detect(project, ['packages']);
  assert.ok(!found.components.some((c) => c.name === 'acme/billing-only'));
  assert.ok(!found.files.includes('packages/billing/composer.lock'));
});
