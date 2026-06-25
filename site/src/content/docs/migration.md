---
title: "Migrating from AccessControl v2 to v3"
description: "Upgrade guide from AccessControl v2 to v3."
---
> ✨ **See what you can do _more_ with v3 →** [WHATS-NEW.md](/accesscontrol/whats-new/)

v3 is a focused modernization. The everyday API — `grant`/`deny`, `can`,
`createAny`/`readOwn`/…, `permission.granted` / `.attributes` / `.filter()` —
is unchanged, so most code keeps working. This guide covers the breaking points
and shows the "same result in v3" for each.

---

## 1. ESM-only

v3 ships as **ES Modules**.

```js
// v2 (CommonJS)
const { AccessControl } = require('accesscontrol');

// v3 (ESM)
import { AccessControl } from 'accesscontrol';
```

Use a modern Node/bundler. If you're stuck on CommonJS, stay on v2.

## 2. Grants Model Shape (`getGrants()` Output)

The stored shape changed so possession is a **field** and each action maps to an
**array of rules** (enabling conditions, deny rules, and multiple rules per
action). The everyday builder API that produces it is the same.

```js
// v2 — possession folded into the action key, attributes inline
{ admin: { video: { 'read:any': ['*'], 'delete:own': ['*'] } } }

// v3 — action key + possession field + rule array
{ admin: { video: {
  read:   [{ possession: 'any', attributes: ['*'] }],
  delete: [{ possession: 'own', attributes: ['*'] }],
} } }
```

If you persisted the **object** form from `getGrants()` in v2, re-export it from
v3 once (`ac.getGrants()` / `ac.getGrantsList()`) and store the new shape. The
flat-list form is recommended for databases — see "immutable copies" below.

## 3. Inheritance in the Flat List Uses `$extend` Rows

When defining grants as a flat array, inheritance now travels as its own row.

```js
// v3 flat list
new AccessControl([
  { role: 'editor', resource: 'post', action: 'read:any', attributes: ['*'] },
  { role: 'admin', $extend: ['editor'] }, // inheritance row
]);
```

The programmatic form is unchanged: `ac.grant('admin').extend('editor')` or
`ac.extendRole('admin', 'editor')`.

## 4. Name Handling: Case-preserving + Restricted Charset

v2 normalized names loosely. v3 is **case-preserving** and validates against
`[A-Za-z0-9_-]` (plus the reserved separators below). Two consequences:

- `Admin` and `admin` are now **distinct** roles (no silent lowercasing). Pick a
  convention and stick to it.
- `:` (action/possession), `/` (group/category), and `$` are **reserved** and
  rejected inside a name. Spaces and dots are rejected too.

```js
ac.grant('Admin').readAny('post');   // distinct from 'admin'
ac.grant('send mail');               // ❌ throws (space) — use 'send-mail' / 'sendMail'
```

Need international names? Opt into Unicode (mind the homograph caveat):
`new AccessControl(grants, { engine: { charset: Charset.UNICODE } })`. See
[Strict Mode, Errors & Names](/accesscontrol/concepts/strict/#charset).

## 5. Deny-overrides (Inheritance Override Fix, #34)

An explicit `deny` now restricts **inherited** grants too — deny always wins.
A *smaller child grant no longer shrinks* an inherited grant (grants are purely
additive); to take access away, `deny` it.

```js
ac.grant('user').readAny('post', ['*']);
ac.grant('moderator').extend('user');
ac.deny('moderator').readAny('post', ['secret']);   // carve a field back

ac.can('moderator').readAny('post').attributes;     // ['*', '!secret']
```

`deny` does **not** cascade across possession: `deny create:any` still leaves
`create:own`.

## 6. Enforced Ownership & `strict` (Mostly Opt-in)

`own` checks can now actually verify ownership (see [WHATS-NEW](/accesscontrol/whats-new/)). This is
**backward-compatible by default**: with no ownership resolver configured, `own`
behaves exactly like v2 (it selects the `own` attribute set; you enforce
ownership). You only get enforcement when you opt in:

```js
const ac = new AccessControl(grants, { policy: { ownerField: 'ownerId' } });
// now `own` checks compare ctx.user.id to ctx.<resource>.ownerId
```

`strict.roles` defaults **on** and throws on an unknown role at check time — the
same as v2's throw-on-unknown-role. Set `policy: { strict: { roles: false } }`
for lenient behavior.

## 7. `getGrants()` Returns Immutable Copies

`getGrants()` / `getGrantsList()` / `getRequirements()` return frozen deep copies.
Don't mutate them — go through `grant`/`deny`/`setGrants`/`extendRole`. For
databases, prefer the flat list:

```js
const rows = ac.getGrantsList();        // DB-friendly rows
const restored = new AccessControl(rows); // round-trips identically
```

## 8. Constructor Options & Method Aliases

- The constructor takes a second argument:
  `new AccessControl(grants, { engine, policy, context })` —
  **`engine`** (library mechanics: `pathPrefix`, `allowRegex`, `charset`,
  `safeErrors`), **`policy`** (your model: `ownerField`/`owner`, `strict`,
  allow-lists), **`context`** (data conditions read via `$.`).
- Redundant method aliases were removed in favor of the canonical names. The one
  intentional alias is **`.do()`** (alias of `.action()`), which also covers CRUD:
  `ac.can('admin').do('update', 'post')`.
- New `engine` knobs for production: `allowRegex` (the `matches` operator is now
  opt-in), `safeErrors` (redacted error messages, default on) with a stable
  `err.code`, and `charset`. New `tryCan()` is a fail-closed `can()` — prefer it
  on the request path. See [What's New §10](/accesscontrol/whats-new/) and
  [Security Considerations](/accesscontrol/security/).

---

## Quick Reference

| v2 | v3 |
| --- | --- |
| `require('accesscontrol')` | `import { AccessControl } from 'accesscontrol'` |
| `{ 'read:any': ['*'] }` (stored) | `{ read: [{ possession: 'any', attributes: ['*'] }] }` |
| inheritance row (implicit) | `{ role, $extend: [...] }` |
| names lowercased | names case-preserving, `[A-Za-z0-9_-]` |
| child grant shrinks inherited | grants additive; use `deny` (deny-overrides) |
| `own` = attribute set only | `own` enforced when `ownerField`/`owner` configured |
| mutable `getGrants()` | frozen copy; use `getGrantsList()` for DBs |

> ✨ **See what you can do _more_ with v3 →** [WHATS-NEW.md](/accesscontrol/whats-new/)

