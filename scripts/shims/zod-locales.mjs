// SPDX-License-Identifier: GPL-3.0-or-later
// Stands in for zod's locales index when bundling: zod's error messages in 60 languages are about a
// third of the bundle, and only English is used (zod sets it as the default by itself).
export { default as en } from '../../node_modules/zod/v4/locales/en.js';
