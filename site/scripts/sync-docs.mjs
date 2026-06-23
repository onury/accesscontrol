// Pulls AccessControl's repo-root CHANGELOG into the Starlight content collection
// at build time (all other pages are authored directly in src/content/docs/).
// The engine lives in @onury/docs-kit; this file declares WHICH root files map to
// WHICH in-site pages.
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { syncDocs } from '@onury/docs-kit/sync';

const here = dirname(fileURLToPath(import.meta.url));

syncDocs({
  root: resolve(here, '../..'), // project root (one level above site/)
  outDir: resolve(here, '../src/content/docs'),
  base: '/accesscontrol',
  files: [
    {
      src: 'CHANGELOG.md',
      out: 'changelog.md',
      title: 'Changelog',
      description: 'Release history — notable changes across versions.'
    }
  ]
});
