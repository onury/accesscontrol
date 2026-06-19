# Issue comments (v3 launch) — DRAFTS

Working notes for closing the upstream **onury/accesscontrol** issues that v3
resolves. Each block is a ready-to-post comment written in my own voice — review
and tweak the wording before posting, then comment + close on launch.

> ⚠️ Do **not** auto-post these. This file is local only; nothing here touches
> the onury repo. Links point to the source docs on GitHub
> (`github.com/onury/accesscontrol`), not the docs site.

Resolved by v3 (cited in `CHANGELOG.md`): #14, #23, #24, #25, #33, #34, #35, #36,
#41, #46, #58, #87, #90, #96, #103, #106, #108.

Reject/close drafts (out of scope, by design, or answered): #42, #44, #47, #93,
#95, #97, #98, #101, #102, #110, #111, #115.

Deferred to a later version (kept open): #91.

---

## #34 — Explicit `.grant()` and `.deny()` should override any inherited permissions  _(open)_

This is implemented in v3 as **deny-overrides**. An explicit `deny` now restricts
inherited (extended) grants too, and deny always wins. Grants are purely additive
— a smaller child grant no longer silently shrinks an inherited one; to take
access away, you `deny` it. Deny does not cascade across possession, so
`deny create:any` still leaves `create:own` intact.

```js
ac.grant('admin').readAny('post', ['*']);
ac.deny('admin').readAny('post', ['secret']);
ac.can('admin').readAny('post').attributes; // ['*', '!secret']
```

Shipped in **v3.0.0**. Closing — thanks for the detailed report.
Docs: https://github.com/onury/accesscontrol/blob/master/docs/WHATS-NEW.md

---

## #35 — Add conditions to grants  _(open)_

This is the flagship feature of v3. You can attach a declarative condition to any
grant with `.where()` — written as readable string sugar or canonical JSON — and
it decides whether the grant applies at check time, against per-check context:

```js
ac.grant('manager').where('$.order.value <= 100000').updateAny('order', ['*']);
ac.can('manager', { order: { value: 5000 } }).updateAny('order').granted; // true
```

Operators: `== != > >= < <=`, `in`, `contains`, `matches`, `startsWith`,
`endsWith`, `before`/`after`/`between`, `cidr`; compose with `{ and, or, not }`.
Conditions stay JSON-serializable, so they persist cleanly to a database.

Shipped in **v3.0.0**. Closing. Docs:
https://github.com/onury/accesscontrol/blob/master/docs/WHATS-NEW.md

---

## #41 — Add environments and object conditions  _(open)_

Covered by the new conditions engine in v3. Environment/context values are read
via `$.` inside a condition (with `$.now.*` auto-injected for time checks), and
object conditions are expressed as canonical JSON and composed with
`{ and, or, not }`:

```js
ac.grant('admin')
  .where({ and: ['$.env == prod', '$.ip cidr 10.0.0.0/8'] })
  .readAny('server');
```

Shipped in **v3.0.0**. Closing. Docs:
https://github.com/onury/accesscontrol/blob/master/docs/WHATS-NEW.md

---

## #87 — Custom actions (and checking many permissions)  _(open)_

Custom (non-CRUD) actions are in v3. Any action name works via `.action()` / its
alias `.do()`, with the same possession / ownership / condition machinery:

```js
ac.grant('editor').action('publish', 'article', ['*']);
ac.grant('author').action('publish:own', 'article', ['*']);
ac.can('author', { user, article }).do('publish:own', 'article').granted;
```

For checking permissions in templates/handlers without nested conditionals, use
`tryCan()` — it's a fail-closed `can()` that never throws, so it's safe on the
request path:

```js
if (ac.tryCan(role).do('publish', 'article').granted) { /* ... */ }
```

Shipped in **v3.0.0**. Closing. Docs:
https://github.com/onury/accesscontrol/blob/master/docs/WHATS-NEW.md

---

## #46 — Dynamic Actions and Possession Groups  _(open)_

The dynamic-actions part landed in v3: any non-CRUD action name works via
`.action()` / `.do()`, with full possession/ownership/condition support (see
#87). On "possession groups" — I kept possession to `own`/`any` (now backed by
the conditions engine and actually enforced) rather than introducing new
possession kinds; anything finer-grained is expressed with a condition via
`.where()`. If you were after a specific case that conditions don't cover, let me
know and I'll reopen.

Shipped in **v3.0.0**. Closing. Docs:
https://github.com/onury/accesscontrol/blob/master/docs/WHATS-NEW.md

---

## #58 — Wildcard for user and resource  _(open)_

I decided against literal `*` wildcards for roles/resources — granting to
"everything" is a data-leak footgun and makes audits hard to reason about.
Instead, v3 ships the safer equivalent: **bounded role groups and resource
categories**. Declare a vocabulary once with `setup()`, then grant to a group or
category and it reaches every member dynamically:

```js
ac.setup({
  roles:     { admins: ['admin', 'moderator'] },
  resources: { media:  ['photo', 'video'] },
});
ac.grant('admins').readAny('media'); // group × category, every member
```

This gives the one-shot bulk grant you were after, without the blast radius of
`*`. Shipped in **v3.0.0**. Closing. Docs:
https://github.com/onury/accesscontrol/blob/master/docs/WHATS-NEW.md

---

## #103 — Grant permissions for every resource?  _(open)_

In v3, do this with a bounded **resource category** (and/or role group) rather
than a risky `*`. Declare the category once and grant to it; it covers every
member:

```js
ac.setup({ resources: { media: ['photo', 'video', 'audio'] } });
ac.grant('admin').readAny('media'); // → media/photo, media/video, media/audio
```

A category is the explicit, audit-friendly way to express "all of these". Shipped
in **v3.0.0**. Closing. Docs:
https://github.com/onury/accesscontrol/blob/master/docs/WHATS-NEW.md

---

## #23 — Filtering inside an array of collections  _(open)_

`permission.filter()` accepts an array of objects in v3 and filters each element
against the granted attributes (same Notation globs, negations included):

```js
const perm = ac.can('user').readAny('post');
const safe = perm.filter(arrayOfPosts); // array in → filtered array out
```

Shipped in **v3.0.0**. Closing. Docs:
https://github.com/onury/accesscontrol/blob/master/docs/WHATS-NEW.md

---

## #24 — Combined own-or-any check  _(open)_

v3 handles this with the possession cascade: a blanket `any` grant automatically
satisfies an `own` check, so you no longer have to test both. Query `own` and a
user holding `any` still passes; query `any` and only `any` passes. Paired with
enforced ownership (`policy.ownerField` / `policy.owner`), `own` is verified for
real instead of only selecting the `own` attribute set.

Shipped in **v3.0.0**. Closing. Docs:
https://github.com/onury/accesscontrol/blob/master/docs/WHATS-NEW.md

---

## #25 — Should we remove aliases in v3?  _(open)_

Yes — done. v3 removes the redundant aliases (`allow()`, `reject()`, `query()`,
`inherit()`, `getExtendedRolesOf()`, `isAccessControlError()`) in favor of the
canonical names. The CRUD shortcuts (`createAny()`/`readOwn()`/…) stay, and there
is one intentional new alias: `.do()` ↔ `.action()` for the generic action API.

Shipped in **v3.0.0**. Closing. Docs:
https://github.com/onury/accesscontrol/blob/master/docs/MIGRATION.md

---

## #90 — Make `Action` and `Possession` actual enums  _(open)_

Done in v3 — both are real enums now, available as named imports:

```js
import { Action, Possession } from 'accesscontrol';
```

(Alongside new `Charset`, `ErrorCode`, and `AccessControlEvent` enums.) Shipped in
**v3.0.0**. Closing.

---

## #96 — Consider upgrading Notation to latest  _(open)_

Done — and then some: v3 is built on `notation` v3 (using `NotationGlob.union`
and `Notation#filter`). Shipped in **v3.0.0**. Closing.

---

## #14 — Does `readOwn` include `readAny` inheritance?  _(already closed)_

> Already closed upstream — keep this only if it needs a definitive v3 answer or
> gets reopened.

In v3 this is well-defined: an `any` grant satisfies an `own` check via the
possession cascade, so a role that can `readAny` can also `readOwn`. And `own` is
now actually **enforced** when you configure ownership (`policy.ownerField` or a
custom `policy.owner` resolver) — `readOwn` verifies the record belongs to the
requester rather than only selecting the `own` attribute set.

Docs: https://github.com/onury/accesscontrol/blob/master/docs/WHATS-NEW.md

---

## #36 — Add action/possession info to the `Permission` instance  _(open)_

Added in v3. A `Permission` now exposes `action` (the bare verb checked) and
`possession` alongside the existing `granted`/`grantedAsync`, `attributes`,
`roles`, `resource`:

```js
const perm = ac.can('user', ctx).readOwn('post');
perm.action;     // 'read'
perm.possession; // 'own' or 'any'
```

`possession` is the **resolved** value — because `any` ⊇ `own`, a query for `own`
that's satisfied via an `any` grant reports `'any'` (so you can tell *how* access
was granted). Shipped in **v3.0.0**. Closing. Docs:
https://github.com/onury/accesscontrol/blob/master/docs/WHATS-NEW.md

---

## #33 — Get possible actions for role(s)  _(open)_

Added in v3. `getActions()` returns the action names in the model; pass a role
(or roles) to scope it to what that role can do, **including inherited** actions:

```js
ac.getActions();        // all actions
ac.getActions('admin'); // actions available to 'admin' (own + inherited)
```

Shipped in **v3.0.0**. Closing. Docs:
https://github.com/onury/accesscontrol/blob/master/docs/WHATS-NEW.md

---

## #108 — Cannot inherit a role defined in the same grants object  _(open)_

This is fixed in v3 — object-form `$extend` resolves regardless of declaration
order, so a role can inherit a sibling defined anywhere in the same object:

```js
new AccessControl({
  paid: { $extend: ['base'] },                                   // forward ref — fine
  base: { post: { read: [{ possession: 'any', attributes: ['*'] }] } }
});
```

It only throws when the parent genuinely isn't defined. Shipped in **v3.0.0** —
closing. Thanks for the report.

---

## #106 — Support for Deno  _(open)_

v3 is pure ESM with no Node-only built-in dependencies, so it runs on Deno (and
Bun). On Deno, import via the `npm:` specifier — no install step:

```js
import { AccessControl } from 'npm:accesscontrol';
```

Shipped in **v3.0.0**. Closing. Docs:
https://github.com/onury/accesscontrol/blob/master/docs/WHATS-NEW.md

---

# Reject / close — out of scope, by design, or answered

> Drafts for issues that won't get a code change. Tone: appreciative but clear.
> Re-word as you like before posting.

## #110 — Why does `updateOwn` filter `req.body` instead of throwing?  _(close: by design)_

By design. A permission answers two separate questions: **whether** access is
granted (`granted`) and **which fields** are allowed (`attributes`). `filter()`
applies the second — it strips disallowed fields so an over-posted payload can't
write them, without failing the whole request. If you'd rather reject, check the
fields yourself and return 403; the library gives you both `granted` and
`attributes` to decide. Closing — happy to clarify further.

## #98 — Rules / restrict an author to their own articles  _(close: answered by v3)_

v3 supports this directly. Configure ownership and grant `own`; the library
enforces that the record belongs to the requester:

```js
const ac = new AccessControl({}, { policy: { ownerField: 'authorId' } });
ac.grant('author').updateOwn('article', ['*']);
ac.can('author', { user, article }).updateOwn('article').granted;
```

For attribute/environment rules, use `.where()` conditions. See the
[recipe](https://github.com/onury/accesscontrol/blob/master/website/src/content/docs/guides/recipes.md).
Closing.

## #101 — Show/hide a page element by role  _(close: usage / out of scope)_

AccessControl gives you the decision; rendering is your app's job:

```js
if (ac.tryCan(role).readAny('dashboard:revenue').granted) showWidget();
```

How you wire that into a template/React tree is up to you — there's a short
recipe in the docs. UI gating is UX, not a security boundary; always re-check on
the server. Closing.

## #95 — Sharing one policy across microservices  _(close: app-level, but here's the pattern)_

The library deliberately stays out of transport, but it gives you everything to
distribute the model: it serializes to plain JSON via `snapshot()` (grants +
gates + vocabulary) or `getGrantsList()` (DB rows). Keep one source of truth,
persist the snapshot, and `restore()` it in each service on boot:

```js
await store.put('policy', JSON.stringify(ac.snapshot()));
const ac = new AccessControl().restore(await store.get('policy'));
```

Move the blob however suits you (shared store, config mount, or a small policy
service) and run the check locally in each service. Recipe in the docs. Closing
as it's an application concern rather than a library feature.

## #93 — Allow `number` as a role type  _(close: out of concept)_

Roles in AccessControl are **named strings** (validated against a charset, with
`:` `/` `$` reserved). Numeric identifiers are usually *user* ids, not roles —
coerce with `String(id)` at your boundary if you really want numeric role keys.
I'd rather keep names a single, predictable type. Closing.

## #44 — Access control editor (GUI)  _(close: out of scope)_

A visual editor is a separate tool/project rather than something the core library
should ship. The model is plain JSON (`snapshot()` / `getGrantsList()`), so a
third-party editor can read and write it. Closing the core issue.

## #42 — Contribution & roadmap  _(close: superseded)_

There's now a published roadmap and contributing flow. Closing in favor of those.

## #47 — A spec for AccessControl  _(close: superseded by docs)_

The v3 documentation now covers the model and semantics in depth (concepts,
migration, security). Closing — open a focused issue if a specific behavior needs
pinning down.

## #97 — Is this repo abandoned?  _(close)_

Not abandoned — v3 is a substantial release. Closing.

## #102 — Offer to become a maintainer  _(close: governance)_

Thanks for offering. Closing the issue; let's take maintainer/governance topics
to a direct conversation.

## #115 — React support  _(close: framework-agnostic)_

AccessControl is framework-agnostic — there's nothing React-specific to add. Call
it (typically on the server) and consume the booleans/filtered data in your
components; there's a short React recipe in the docs. Closing.

## #111 — Control system  _(close: needs info)_

I can't tell what's being requested here. Closing as needs-info — please reopen
with a concrete use case or repro and I'll take a look.

---

## Deferred (no comment — keep open for a later version)

- **#91 — Ignore undefined roles if at least one grants access.** Fits the
  multi-role union model, but conflicts with `strict.roles: true` (fail-fast).
  Worth a deliberate opt-in mode later (e.g. lenient multi-role). Note:
  `strict.roles: false` already covers the fully-lenient case today.
