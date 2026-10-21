// SPDX-License-Identifier: GPL-3.0-or-later
// Stands in for is-unsafe's index when bundling. fast-xml-parser only imports isUnsafe and the HTML
// and XML pattern lists; the package index also pulls in every other list (shell, SQL, NoSQL,
// ReDoS, log), which would ship unused and whose shell rules read as download-and-run commands to
// scanners. The lists themselves are is-unsafe's own files, unchanged; isUnsafe matches its
// behaviour for the arguments it accepts.
import HTML from '../../node_modules/is-unsafe/src/contexts/html.js';
import XML from '../../node_modules/is-unsafe/src/contexts/xml.js';

HTML.label = 'HTML';
XML.label = 'XML';

export { HTML, XML };

/**
 * True when value matches any rule of the given pattern list, list of pattern lists, or RegExp.
 * @param {string} value
 * @param {RegExp | { pattern: RegExp }[] | { pattern: RegExp }[][]} context
 */
export function isUnsafe(value, context) {
  if (typeof value !== 'string') throw new TypeError(`is-unsafe: first argument must be a string, got ${typeof value}`);
  if (context instanceof RegExp) return context.test(value);
  if (!Array.isArray(context) || context.length === 0) throw new TypeError('is-unsafe: context must be a non-empty pattern list, a list of them, or a RegExp');
  const lists = Array.isArray(context[0]) ? context : [context];
  return lists.some((list) => list.some((rule) => rule.pattern.test(value)));
}
