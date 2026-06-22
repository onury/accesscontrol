// Pulls AccessControl's root markdown into the Starlight content collection at
// build time. The engine lives in @onury/docs-kit; this file declares WHICH
// files map to WHICH in-site pages.
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { syncDocs } from '@onury/docs-kit/sync';

const here = dirname(fileURLToPath(import.meta.url));

syncDocs({
  root: resolve(here, '../..'),
  outDir: resolve(here, '../src/content/docs'),
  base: '/accesscontrol',
  files: [
    {
      src: 'docs/WHATS-NEW.md',
      out: 'whats-new.md',
      description: 'New capabilities in AccessControl v3.'
    },
    {
      src: 'docs/MIGRATION.md',
      out: 'migration.md',
      description: 'Upgrade guide from AccessControl v2 to v3.'
    },
    { src: 'docs/FAQ.md', out: 'faq.md', description: 'Frequently asked questions.' },
    {
      src: 'CHANGELOG.md',
      out: 'changelog.md',
      title: 'Changelog',
      description: 'Release history — notable changes across versions.'
    }
  ]
});
