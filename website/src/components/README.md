# Starlight component overrides

Ready‑to‑edit overrides for Starlight's built‑in UI components. They're **inert
until you enable them** — Astro only builds a component when something imports
it, and these are referenced only via the (commented‑out) `components` map in
`../../astro.config.mjs`.

## How to enable one

1. Edit the stub here (e.g. `Footer.astro`).
2. In `astro.config.mjs`, inside `starlight({ … })`, uncomment the `components`
   map and the line for that component:

   ```js
   starlight({
     // …
     components: {
       Footer: './src/components/Footer.astro',
       // Head: './src/components/Head.astro',
       // Hero: './src/components/Hero.astro',
       // SocialIcons: './src/components/SocialIcons.astro',
     },
   })
   ```

3. Restart `npm run docs:dev`.

## The pattern

Each stub re‑renders Starlight's **default** component, so you keep all built‑in
behavior and just add around it:

```astro
---
import Default from '@astrojs/starlight/components/Footer.astro';
---
<Default><slot /></Default>
<!-- your extra markup here -->
```

If you want to *replace* the default entirely, drop the `<Default />` line and
render your own markup. Your component receives Starlight's route data via
`Astro.locals.starlightRoute` (e.g. `const { entry } = Astro.locals.starlightRoute`).

## Provided stubs

| File | Overrides | Use it for |
| --- | --- | --- |
| `Head.astro` | `Head` | analytics, extra `<meta>`/`<link>`, preconnect |
| `Footer.astro` | `Footer` | custom footer content under prev/next nav |
| `Hero.astro` | `Hero` | the splash/home banner (`index.mdx` `hero:`) |
| `SocialIcons.astro` | `SocialIcons` | a button next to the header social links |

## Everything else you can override

Any built‑in component can be overridden the same way — create
`src/components/<Name>.astro` and add it to the `components` map. Common ones:

- **Head/SEO:** `Head`
- **Header:** `Header`, `SiteTitle`, `Search`, `SocialIcons`, `ThemeSelect`,
  `LanguageSelect`
- **Sidebars:** `Sidebar` (left nav), `PageSidebar` + `TableOfContents` (right),
  `MobileMenuToggle`
- **Content:** `PageTitle`, `Hero`, `Banner`, `ContentPanel`, `MarkdownContent`,
  `DraftContentNotice`, `FallbackContentNotice`
- **Footer:** `Footer`, `LastUpdated`, `Pagination`, `EditLink`
- **Page shell:** `PageFrame`, `TwoColumnContent`, `Page`

Full reference (every overridable component + the props each receives):
https://starlight.astro.build/reference/overrides/

General guide: https://starlight.astro.build/guides/overriding-components/

> Tip: prefer **config** and **CSS** before overriding a component. Logo, social
> links, edit link, favicon, fonts and the whole color scheme are all doable in
> `astro.config.mjs` and `src/styles/theme.css` / `custom.css` — overrides are
> for when you need different *markup*.
