<h1 align="center">
    <a href="https://onury.io/accesscontrol"><img width="465" height="170" src="https://raw.github.com/onury/accesscontrol/master/ac-logo.png" alt="AccessControl.js" /></a>
</h1>
<p align="center">
  <a href="https://github.com/onury/accesscontrol/actions/workflows/ci.yml"><img src="https://github.com/onury/accesscontrol/actions/workflows/ci.yml/badge.svg" alt="build" /></a>
  <a href="#security--quality"><img src="https://img.shields.io/badge/coverage-100%25-2BB150?logo=vitest&logoColor=%23FDC72B&style=flat" alt="coverage" /></a>
  <a href="https://stryker-mutator.io/docs/"><img src="https://img.shields.io/badge/mutation-88%25-2BB150?style=flat" alt="mutation score" /></a>
  <a href="https://www.npmjs.com/package/accesscontrol"><img src="https://img.shields.io/npm/v/accesscontrol.svg?style=flat&label=&color=%23C6234B&logo=npm" alt="version" /></a>
  <a href="https://www.npmjs.com/package/accesscontrol"><img src="https://img.shields.io/npm/dm/accesscontrol.svg?style=flat&color=2BB150" alt="downloads" /></a>
  <a href="https://gist.github.com/onury/d3f3d765d7db2e8b2d050d14315f2ac7"><img src="https://img.shields.io/badge/ESM-F7DF1E?style=flat" alt="ESM" /></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TS-3260C7?style=flat" alt="TS" /></a>
  <a href="https://github.com/onury/accesscontrol/blob/master/LICENSE"><img src="https://img.shields.io/npm/l/accesscontrol.svg?style=flat&color=blue" alt="license" /></a>
  <a href="https://onury.io/accesscontrol"><img src="https://img.shields.io/badge/docs-read-c27cf4?style=flat" alt="documentation" /></a>
</p>

<p align="center">© 2026, Onur Yıldırım (<b><a href="https://github.com/onury">@onury</a></b>).</p>
<br />

### Role and Attribute based Access Control for Node.js

Many [RBAC][rbac] (Role-Based Access Control) implementations differ, but the
basics are widely adopted since they simulate real-life role (job) assignments.
But as data gets more complex, you need to define policies on resources,
subjects, even environments — this is [ABAC][abac] (Attribute-Based Access
Control). Merging the best of both (see this [NIST paper][nist-paper]),
AccessControl implements RBAC basics **and** ABAC conditions, ownership, and
mandatory gates.

> **v3** is **ESM** 🔆 and adds a real policy engine: conditions, enforced
> ownership, custom actions, `require()` gates, groups/categories, async checks
> and audit events.
> &nbsp;✨ **[What's new in v3 →](https://onury.io/accesscontrol/whats-new/)** &nbsp;·&nbsp; ⬆️ **[Migrating from v2 →](https://onury.io/accesscontrol/migration/)**

## Core Features

- Chainable, friendly API — e.g. `ac.can(role).createOwn(resource)`.
- Role hierarchical **inheritance** with **deny-overrides** (deny always wins).
- **Conditions** (`.where()`) — declarative ABAC with a readable expression syntax.
- **Enforced ownership** — `own` actually verifies the record belongs to the user.
- **Custom actions** beyond CRUD via `.action()` / `.do()`.
- **`require()` gates** — mandatory restrictions at global / category / resource scope.
- **Groups & categories** (`/`) — bounded bulk grants; the safe alternative to `*`.
- **Async checks** + custom condition functions (`defineCondition`, `grantedAsync`).
- **Events** — an `access` audit stream, plus `change` / `error`.
- Glob-notation **attribute filtering** of data (with nested objects).
- Define grants **at once** (object or DB rows) or **one by one**; `lock()` the model.
- **Fail-closed checks** — `tryCan()` never throws; a failure can't become "allow".
- **Hardened** — prototype-pollution-safe, ReDoS-guarded opt-in regex, redacted
  error messages with stable `err.code`, optional Unicode charset.
- No **silent** errors. **Fast** (in-memory). Strongly **typed**. ESM.
- **Battle-tested** — 100% coverage, mutation-tested, adversarial + property-fuzz
  suites; sole runtime dependency (`notation`, same author) pinned exactly, zero
  production advisories.

## Installation

```sh
npm i accesscontrol
```

```js
import { AccessControl } from 'accesscontrol';
```

## Quick Start

```js
const ac = new AccessControl();

ac.grant('user')                      // define or modify a role
    .createOwn('video')               // ≡ .createOwn('video', ['*'])
    .deleteOwn('video')
    .readAny('video')
  .grant('admin')                     // switch role, keep the chain
    .extend('user')                   // inherit user's grants
    .updateAny('video', ['title'])    // explicit attributes
    .deleteAny('video');

ac.can('user').createOwn('video').granted;    // true
ac.can('admin').updateAny('video').attributes; // ['title']
```

## Guide

### Roles & Inheritance

Create roles by calling `.grant(role)` or `.deny(role)`. Roles inherit other
roles with `.extend()`; grants are **additive**, and an explicit `deny` always
wins — even over inherited grants.

```js
ac.grant('user').readAny('post', ['*']);
ac.grant('moderator').extend('user');
ac.deny('moderator').readAny('post', ['secret']);   // carve a field back

ac.can('moderator').readAny('post').attributes;     // ['*', '!secret']
```

`deny` does not cascade across possession: `deny create:any` still leaves
`create:own`.

### Actions — CRUD and Custom

The CRUD helpers (`createAny`, `readOwn`, `updateAny`, `deleteOwn`, …) are sugar
over the generic `.action()` / `.do()`, which accept **any** action name:

```js
ac.grant('editor').action('publish', 'article', ['*']);      // publish (any)
ac.grant('author').action('publish:own', 'article', ['*']);  // ownership-gated

ac.can('author', { user, article }).do('publish:own', 'article').granted;
ac.can('admin').do('update', 'post').granted;                // CRUD via .do()
```

### Resources, Attributes & Filtering

Attributes use [glob notation][glob] with negation and nested paths. `filter()`
returns a copy with only the allowed fields.

```js
ac.grant('user').readOwn('account', ['*', '!password', 'profile.*']);

const perm = ac.can('user').readOwn('account');
perm.attributes;                 // ['*', '!password', 'profile.*']
perm.filter(accountRecord);      // record without `password`
```

### Possession & Ownership

`any` means any record; `own` means the requester owns it. Tell AccessControl how
ownership is determined and pass the record in the check context — `own` is then
**enforced**:

```js
const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
ac.grant('user').updateOwn('order', ['*']);

ac.can('user', { user: { id: 7 }, order: { ownerId: 7 } }).updateOwn('order').granted; // true
ac.can('user', { user: { id: 7 }, order: { ownerId: 9 } }).updateOwn('order').granted; // false
```

A custom resolver (`policy.owner`) wins over `ownerField`. With no resolver
configured, `own` keeps its v2 behavior (selects the attribute set; you enforce
ownership). A blanket `any` grant still satisfies an `own` check.

### Conditions — `.where()` and `.with()`

Attach a condition that decides whether a grant applies. Supply per-check data
via `can(role, context)`, the fluent `.with()`, or `check({ context })`.

```js
ac.grant('manager')
  .where('$.order.value <= 100000')
  .updateAny('order', ['*']);

ac.can('manager').with({ order: { value: 5000 } }).updateAny('order').granted; // true
```

Operators: `== != > >= < <=`, `in`, `contains`, `matches`, `startsWith`,
`endsWith`, `before` / `after` / `between`, `cidr`; combine with `{ and, or, not }`.
The time helper `$.now.*` is auto-injected. Conditions also accept canonical JSON
(`['$.order.value', '<=', 100000]`), which is what gets stored/serialized.

> [!NOTE]
> The `matches` (regex) operator is **opt-in** — enable `engine.allowRegex`
> (it's a ReDoS surface). Patterns are then screened for catastrophic
> backtracking. See [Security](https://onury.io/accesscontrol/security/).

### Mandatory Gates — `require()` 

`.where()` conditionally **grants**; `.require()` is an independent gate that can
only **restrict**. `granted = (a grant matches) AND (every applicable gate passes)`.

```js
ac.require('$.env == prod');                            // global
ac.category('billing').require('$.ip cidr 10.0.0.0/8');  // per category
ac.resource('billing/invoice').require('$.mfa == true'); // per resource
```

### Groups & Categories — Bounded Bulk Grants

Declare your vocabulary with `setup()`, then grant to a **group** or **category**
once; members inherit dynamically. `media/photo` and `legal/photo` never collide.

```js
ac.setup({
  roles:     { admins: ['admin', 'moderator'], _: ['user'] },
  resources: { media: ['photo', 'video'], _: ['profile'] },
});
ac.grant('admins').readAny('media');                    // group × category
ac.can('admins/admin').readAny('media/photo').granted;  // true

ac.group('admins').getRoles();        // ['admins/admin', 'admins/moderator']
ac.category('media').getResources();  // ['media/photo', 'media/video']
```

`setup()`'s `roles`/`resources` also accept a plain array when you don't need
grouping (`roles: ['user', 'admin']`).

### Strict Mode

`policy.strict` (boolean or per-key object) turns on loud typo-protection.
Defaults: `checks` and `roles` **on** (secure), `actions` and `resources` **off**.

```js
new AccessControl(grants, { policy: { strict: { actions: true, resources: true } } });
// an unknown action/resource throws instead of silently returning granted:false
```

### Async Checks & Custom Functions

Register business logic and reference it from a grant or gate as `{ fn, args }`
(JSON-serializable). Declarative checks stay synchronous; custom/async ones use
`grantedAsync` / `checkAsync`.

```js
ac.defineCondition('ipAllowed', async (ctx, args) => isAllowed(ctx.ip, args.cidr));
ac.grant('admin').where({ fn: 'ipAllowed', args: { cidr: '10.0.0.0/8' } }).readAny('server');

await ac.can('admin', { ip }).readAny('server').grantedAsync;
```

### Events & Audit

A dependency-free emitter. `access` fires on every resolved check (granted and
denied) — your audit log, with a denial `reason`. Listeners are observational and
isolated; a throwing listener never breaks a check.

```js
ac.on('access', (e) => audit(e));   // { roles, resource, action, granted, reason, ... }
ac.on('change', (e) => log(e.type));
ac.on('error', (e) => report(e.error));
```

### Serialization (for Databases)

```js
const rows = ac.getGrantsList();          // flat, DB-friendly rows (+ $extend rows)
const restored = new AccessControl(rows); // round-trips identically
ac.getGrants();                           // the object form (frozen copy)
ac.getRequirements();                     // require() gates by scope
ac.getVocabulary();                       // setup() input: { roles, resources, actions }

// or persist/restore the whole model (grants + gates + vocabulary) in one call:
await db.savePolicy(JSON.stringify(ac.snapshot()));
const ac2 = new AccessControl().restore(await db.loadPolicy());
```

Both object and list inputs are accepted by the constructor and `setGrants()`.
See **[examples/](./examples)** for a full grants model, an SQL schema, and an
Express integration.

### `engine` vs `policy` vs `context`

The constructor takes `new AccessControl(grants, { engine, policy, context })` —
three concerns: **`engine`** (library mechanics & security: `pathPrefix`,
`allowRegex`, `charset`, `safeErrors`), **`policy`** (your authorization model:
`ownerField`/`owner`, `strict`, allow-lists), and **`context`** (ambient data
conditions read via `$.`). Rule of thumb: *library → `engine`, your domain →
`policy`, condition data → `context`.*

### Express Middleware

```js
function authorize(action, resource, loadRecord) {
  return async (req, res, next) => {
    const record = loadRecord ? await loadRecord(req) : undefined;
    const ctx = { env: process.env.NODE_ENV, user: req.user, [resource]: record };
    const perm = ac.can(req.user.role, ctx).action(action, resource);
    if (!perm.granted) return res.status(403).end();
    req.permission = perm;
    next();
  };
}

router.get('/articles/:id', authorize('read:any', 'article'), async (req, res) => {
  const article = await db.findArticle(req.params.id);
  res.json(req.permission.filter(article)); // filtered to granted attributes
});
```

A fuller version (ownership, custom actions, audit) lives in
[`examples/express-middleware.example.ts`](./examples/express-middleware.example.ts).

## Security & Quality

Authorization is sensitive, so AccessControl is hardened against the bug classes
that matter for an access-control library — and clear about the decisions left to
you.

- **Fail-closed by design.** Denials return `granted: false`; only genuine faults
  throw. Use `tryCan()` on the request path so a thrown error can never become an
  accidental *allow*. Errors carry a stable `err.code`.
- **Prototype-pollution-safe.** The gadget names `__proto__` / `prototype` /
  `constructor` are rejected, and every name-keyed lookup uses `Object.hasOwn`, so
  a name like `toString` is treated as data, never a prototype member.
- **ReDoS-guarded.** The `matches` regex operator is opt-in (`engine.allowRegex`);
  enabled, patterns are screened for catastrophic backtracking. Condition nesting
  depth is bounded.
- **No info leaks by default.** `engine.safeErrors` (on by default) keeps
  caller-supplied values out of error messages; immutable getters and `lock()`
  prevent tampering.
- **Homograph-aware names.** ASCII by default; `Charset.UNICODE` is opt-in with a
  documented homograph caveat.

> [!IMPORTANT]
> On the request path, treat a thrown error as **deny**, never allow — or just
> use `tryCan()`, which never throws.

> [!NOTE]
> **Quality bar:** 100% coverage (statements/branches/functions/lines),
> mutation-tested (Stryker), plus an adversarial security suite and a seeded
> property fuzzer. Its only runtime dependency (`notation`, from the same author)
> is pinned exactly; `npm audit --omit=dev` reports zero advisories. Full
> details: **[Security Considerations][security]**.

## Documentation

See the full documentation & API reference @ [onury.io/accesscontrol](https://onury.io/accesscontrol)

## License

[**MIT**][license].

[license]:https://github.com/onury/accesscontrol/blob/master/LICENSE
[docs]:https://onury.io/accesscontrol/
[security]:https://onury.io/accesscontrol/security/
[best]:https://onury.io/accesscontrol/best-practices/
[rbac]:https://en.wikipedia.org/wiki/Role-based_access_control
[abac]:https://en.wikipedia.org/wiki/Attribute-Based_Access_Control
[glob]:https://github.com/onury/notation
[nist-paper]:http://csrc.nist.gov/groups/SNS/rbac/documents/kuhn-coyne-weil-10.pdf
[changelog]:https://github.com/onury/accesscontrol/blob/master/CHANGELOG.md
