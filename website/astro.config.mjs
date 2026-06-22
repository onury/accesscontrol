// @ts-check
// Per-project Astro + Starlight config.
//
// The shared *theme* comes from @onury/docs-kit via the CSS string paths in
// `customCss` below (resolved at build time). NOTE: do NOT `import` anything
// from `@onury/docs-kit` here — it is an ESM-only package, and importing it into
// the Astro config makes Vite externalize `@astrojs/starlight` and load its
// TypeScript entry under Node, which fails on Node ≥22.18. The small plumbing
// (the constructor-heading remark fix + TypeDoc wiring) is therefore kept inline.
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { createStarlightTypeDocPlugin } from 'starlight-typedoc';

const [starlightTypeDoc, typeDocSidebarGroup] = createStarlightTypeDocPlugin();

/**
 * Drops the auto-generated `## Constructors` heading from the TypeDoc API pages
 * (each class has a single constructor, so the section title is noise).
 */
function remarkDropConstructorsHeading() {
  return (/** @type {any} */ tree) => {
    tree.children = tree.children.filter(
      (/** @type {any} */ node) =>
        !(
          node.type === 'heading' &&
          node.depth === 2 &&
          node.children?.length === 1 &&
          node.children[0].value === 'Constructors'
        )
    );
  };
}

// Published as a GitHub Pages *project* site under the `onury.io` custom domain
// (the apex/CNAME lives on the `onury.github.io` user-site repo), so this serves
// at `https://onury.io/accesscontrol`. `base` must match the repo name.
export default defineConfig({
  site: 'https://onury.io',
  base: '/accesscontrol',
  markdown: { remarkPlugins: [remarkDropConstructorsHeading] },
  integrations: [
    starlight({
      title: 'AccessControl',
      description:
        'Role and Attribute based Access Control for Node.js — conditions, enforced ownership, custom actions, gates, groups, async checks and audit events.',
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/onury/accesscontrol' }
      ],
      // Shared theme (from @onury/docs-kit) + this project's bespoke hero.
      customCss: [
        '@onury/docs-kit/styles/custom.css',
        '@onury/docs-kit/styles/theme.css',
        './src/styles/hero.css'
      ],
      plugins: [
        starlightTypeDoc({
          entryPoints: ['../src/index.ts'],
          tsconfig: '../tsconfig.build.json',
          output: 'api',
          sidebar: { label: 'API Reference', collapsed: true },
          typeDoc: { githubPages: false, excludeInternal: true, sort: ['source-order'] }
        })
      ],
      sidebar: [
        {
          label: 'Start Here',
          items: [
            { label: 'Getting Started', slug: 'getting-started' },
            { label: "What's New in v3", slug: 'whats-new' },
            { label: 'Migrating from v2', slug: 'migration' }
          ]
        },
        {
          label: 'Concepts',
          items: [
            { label: 'Roles & Inheritance', slug: 'concepts/roles' },
            { label: 'Actions & Possession', slug: 'concepts/actions' },
            { label: 'Resources, Attributes & Filtering', slug: 'concepts/resources' },
            { label: 'Ownership', slug: 'concepts/ownership' },
            { label: 'Checking Access', slug: 'concepts/checking' },
            { label: 'Conditions (ABAC)', slug: 'concepts/conditions' },
            { label: 'Require Gates', slug: 'concepts/gates' },
            { label: 'Groups & Categories', slug: 'concepts/groups' },
            { label: 'Async & Custom Functions', slug: 'concepts/async' },
            { label: 'Events & Auditing', slug: 'concepts/events' },
            { label: 'Serialization & Databases', slug: 'concepts/serialization' },
            { label: 'Strict Mode, Errors & Names', slug: 'concepts/strict' }
          ]
        },
        {
          label: 'Guides',
          items: [
            { label: 'Best Practices', slug: 'best-practices' },
            { label: 'Security Considerations', slug: 'security' },
            { label: 'Express Integration', slug: 'guides/express' },
            { label: 'Recipes & Integrations', slug: 'guides/recipes' }
          ]
        },
        {
          label: 'Help',
          items: [
            { label: 'FAQ', slug: 'faq' },
            { label: 'Changelog', slug: 'changelog' }
          ]
        },
        typeDocSidebarGroup
      ]
    })
  ]
});
