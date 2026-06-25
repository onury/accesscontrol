---
title: "What's New in AccessControl v3"
description: "New capabilities in AccessControl v3."
---
v3 keeps the friendly, chainable API you know and adds a real **policy engine** on
top of it: conditions, enforced ownership, custom actions, mandatory gates,
groups/categories, async checks, and an audit event stream.

> Upgrading from v2? See **[MIGRATION.md](/accesscontrol/migration/)** for a side-by-side
> "same result in v3" mapping.

---

## 1. Conditions — `.where()` (ABAC)

Attach a declarative condition to a grant; it decides **whether** the grant
applies at check time. Write it as readable string sugar or canonical JSON.

```js
ac.grant('manager')
  .where('$.order.value <= 100000')
  .updateAny('order', ['*']);

ac.can('manager', { order: { value: 5000 } }).updateAny('order').granted;   // true
ac.can('manager', { order: { value: 999999 } }).updateAny('order').granted; // false
```

Operators include `== != > >= < <=`, `in`, `contains`, `matches`, `startsWith`,
`endsWith`, `before`/`after`/`between`, and `cidr`. Combine with `{ and, or, not }`.
The time helper `$.now.*` is auto-injected (overridable for deterministic tests).

Per-check data is supplied via `can(role, context)`, the fluent `.with(context)`,
or `check({ context })`. Ambient defaults go in `new AccessControl(grants, { context })`.

## 2. Enforced Ownership (`own` Actually Means Owned)

In v2, `readOwn`/`updateOwn`/… only chose *which attributes* a user could access —
confirming the record actually belonged to them was left to your code. **In v3,
AccessControl enforces it.** Tell it how ownership is determined once, pass the
record in the check context, and `own` permissions are granted only when the
record belongs to the requester.

```js
const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
ac.grant('user').updateOwn('order', ['*']);

ac.can('user', { user: { id: 7 }, order: { ownerId: 7 } }).updateOwn('order').granted; // true
ac.can('user', { user: { id: 7 }, order: { ownerId: 9 } }).updateOwn('order').granted; // false
```

Use a custom resolver for anything more involved (it wins over `ownerField`):

```js
new AccessControl({}, { policy: { owner: (ctx) => ctx.user.id === ctx.order.creatorId } });
```

A blanket `any` grant still satisfies an `own` check via the cascade. If you
configure ownership but forget to pass the record, `strict.checks` (default
**on**) denies — secure by default. With **no** resolver configured, `own` keeps
its v2 behavior, so existing code isn't silently locked down.

## 3. Custom (Non-CRUD) Actions — `.action()` / `.do()`

Actions are no longer limited to CRUD. Any name works, with the same
possession/ownership/condition machinery.

```js
ac.grant('editor').action('publish', 'article', ['*']);       // publish (any)
ac.grant('author').action('publish:own', 'article', ['*']);   // ownership-gated
ac.can('author', { user, article }).do('publish:own', 'article').granted;
```

`.do()` is the single sanctioned alias of `.action()` and works for CRUD too:
`ac.can('admin').do('update', 'post')`.

## 4. Deny-overrides Resolution

Grants are purely additive; to take access away you `deny`, and **deny always
wins** — including over inherited grants (the v2 inheritance-override fix, #34).

```js
ac.grant('admin').readAny('post', ['*']);
ac.deny('admin').readAny('post', ['secret']);
ac.can('admin').readAny('post').attributes; // ['*', '!secret']
```

`deny` does not cascade across possession: `deny create:any` still leaves
`create:own`.

## 5. `require()` — Mandatory Restriction Gates

Where `.where()` conditionally **grants**, `.require()` is an independent gate
that can only **restrict**. `granted = (a grant matches) AND (every applicable
gate passes)`, so adding a gate can never widen access.

```js
ac.require('$.env == prod'); // global
ac.category('billing').require('$.ip cidr 10.0.0.0/8'); // per category
ac.resource('billing/invoice').require('$.mfa == true'); // per resource
```

## 6. Role Groups & Resource Categories (`/`) — Bounded Bulk Grants

Declare a vocabulary with `setup()`, then grant to a **group** or **category**
once and have it reach every member dynamically (the safe alternative to a `*`
wildcard).

```js
ac.setup({
  roles:     { admins: ['admin', 'moderator'], _: ['user'] },
  resources: { media: ['photo', 'video'], _: ['profile'] },
});
ac.grant('admins').readAny('media'); // group × category
ac.can('admins/admin').readAny('media/photo').granted; // true (inherited + categorized)
```

`media/photo ≠ legal/photo` (no collisions). Introspect with
`ac.group('admins').getRoles()`, `ac.category('media').getResources()`,
`ac.getGroups()`, `ac.removeGroup(...)`.

## 7. Async Checks & Custom Functions

Register business logic and reference it from a grant or gate as
`{ fn, args }` (which stays JSON-serializable). Declarative checks remain
synchronous; custom/async ones use `grantedAsync` / `checkAsync`.

```js
ac.defineCondition('ipAllowed', async (ctx, args) => isAllowed(ctx.ip, args.cidr));
ac.grant('admin').where({ fn: 'ipAllowed', args: { cidr: '10.0.0.0/8' } }).readAny('server');

await ac.can('admin', { ip }).readAny('server').grantedAsync;
```

## 8. Events & Audit Hooks

A built-in, dependency-free emitter. `access` fires on **every** resolved check
(granted and denied) — your audit log, complete with a denial `reason`. `change`
tracks policy edits; `error` reports faults. Listeners are observational only and
isolated (a throwing listener never breaks a check).

```js
ac.on('access', (e) => audit(e)); // { roles, resource, action, granted, reason, ... }
ac.on('change', (e) => log(e.type));
```

## 9. `engine` vs `policy` vs `context`, and Serialization

The constructor takes `new AccessControl(grants, { engine, policy, context })` —
three buckets, three concerns:

- **`engine`** — library mechanics & security: `pathPrefix`, `allowRegex`,
  `charset`, `safeErrors`.
- **`policy`** — your domain's authorization model: `ownerField`/`owner`,
  `strict`, action/resource allow-lists.
- **`context`** — ambient data your conditions read via `$.`.

For serialization: `getGrants()` ⇄ `getGrantsList()` round-trip the model
(object or DB-friendly flat rows); `getRequirements()` exports the `require()`
gates separately and `getVocabulary()` the `setup()` input. Both object and list
inputs are accepted by the constructor.

A model is really three structures (grants, gates, vocabulary), so v3 adds a
one-call pair that bundles all of them:

```js
await db.savePolicy(JSON.stringify(ac.snapshot()));           // persist everything
const ac = new AccessControl().restore(await db.loadPolicy()); // restore everything
```

`snapshot()` returns `{ grants, requirements, vocabulary }`; `restore()` rebuilds
the model from it — a full replace, applied through the validated `setGrants()` /
`setup()` / `require()` paths. See [Serialization & Databases](/accesscontrol/concepts/serialization/).

## 10. Production Hardening

v3 is hardened for the authorization path — see
[Security Considerations](/accesscontrol/security/) for the full story.

- **`tryCan()` — fail-closed checks.** Identical to `can()`, but it never throws:
  an invalid query, a `strict` violation, or a custom/async condition on the sync
  path all resolve to `granted: false`. Use it on the request path so a thrown
  error can't become an accidental *allow*; keep `can()` for boot/tests.

  ```js
  if (ac.tryCan(role).readAny('post').granted) show();
  else deny();
  ```

- **Prototype-pollution-safe.** The gadget names `__proto__`, `prototype` and
  `constructor` are rejected; any name that collides with an inherited member
  (`toString`, …) is treated as plain data, never a prototype member.

- **Opt-in, ReDoS-guarded regex.** The `matches` operator is now off by default;
  enable `engine.allowRegex`. When on, patterns are screened for catastrophic
  backtracking. Condition nesting depth is bounded too.

- **Stable `err.code` + redacted messages.** Every `AccessControlError` carries a
  machine-readable `ErrorCode`; `engine.safeErrors` (default on) keeps
  caller-supplied values out of messages (they stay on `err.role`/etc.).

- **Configurable charset.** Names are ASCII by default (homograph-safe);
  `engine.charset: Charset.UNICODE` opts into international names.

  ```js
  import { AccessControl, Charset, ErrorCode } from 'accesscontrol';
  const ac = new AccessControl(grants, {
    engine: { allowRegex: false, safeErrors: true, charset: Charset.ASCII }
  });
  ```

---

See **[MIGRATION.md](/accesscontrol/migration/)** to move an existing v2 setup over, and the
runnable **[examples/](../examples)** for a full grants model, SQL schema, and an
Express integration.

