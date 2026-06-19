# AccessControl v3 — Roadmap

> Living planning doc for v3. v3 is a breaking, **ESM-only** release. Guiding
> rule for every item below: **enrich the model without losing the "easy to
> understand, easy to implement" feel.** Anything that makes the common case
> harder gets cut or redesigned.
>
> Status legend: ✅ decided · 🟡 recommended (needs sign-off) · 💬 under
> discussion · ⏳ deferred to a later v3.x

## Principles
- Keep the friendly, readable API (`grant`/`can`/CRUD) front and center.
- Data must import cleanly from a DB (rows / JSON / JSONB) — like ConfGuard.
- New power (conditions, custom actions) is **additive and opt-in**; the simple
  path stays simple.

## 1. Module & build
- ✅ ESM-only (no CJS). (`package.json` already `type:module`.)
- ✅ No `postinstall` "breaking version" banner (anti-pattern; often
  blocked/ignored). Rely on the major bump + a loud README/CHANGELOG migration
  guide; optionally `npm deprecate 'accesscontrol@<3'`. *(notes: "Warning in npm
  CLI")*
- ✅ Split `src/utils.ts` (~874 lines, 32 helpers) into focused modules
  (e.g. `arrays`, `validation`, `grants`, `roles`, `resolution`, `notation`).

## 2. API cleanup
- ✅ Remove aliases: `allow()`, `reject()`, `query()`, `inherit()`,
  `getExtendedRolesOf()`, `isAccessControlError()`. **Keep** `create()`↔
  `createAny()` etc. *(issue #25)* — **one intentional new alias:** `.do()` ↔
  `.action()` (generic action method, §6).
- ✅ Immutable getters: `getGrants()`, `Permission.roles`, `Permission.attributes`
  return frozen copies instead of live internal references.

## 3. Correctness fixes
- ✅ `IGrantsList`/array (DB-row) form must support `$extend` (currently only the
  object form does — `validRoleObject` vs the array branch of
  `getInspectedGrants`). Critical for DB import. *(notes: known issue)*
- ✅ Explicit `.deny()` restricts inherited (extended) grants — **deny-overrides**
  (grants additive, deny subtracts, deny wins). Full algorithm in §5.6.
  *(issue #34)*
- ✅ `['!password']` → normalize a negation-only attribute list to imply `*`
  (i.e. `['!password']` ≡ `['*','!password']`), so it grants "all but password"
  and `granted === true`. Matches intent; v3-appropriate behavior change.
  *(notes: opening question)*

## 4. Error model & tooling parity
- ✅ Upgrade `AccessControlError` to carry structured context (`cause` +
  fields like `role`/`resource`/`action`), matching `ConfGuardError`.
- ✅ Tooling parity with the sibling repos: `biome-config-oy`, `tsconfig-oy`,
  Stryker mutation testing, coverage thresholds.

## 5. Conditions & Context — flagship feature *(issue #35)*
Goal: support policy/context restriction (environment, IP, date/time) **and**
custom business logic, with a clean API and DB-serializable storage. Avoid the
ugly hand-written-JSON feel of role-acl/ladon by pairing declarative storage
with a fluent builder.

### 5.0 Data model & instance buckets (LOCKED)
- ✅ **`Grant`** = one rule for an action on a resource. Stored as an **array of
  `Grant`s** per action (Option B — multiple conditional rules per action), so a
  role can have several rules with different conditions/attributes:
  ```ts
  grants[role][resource][action] = Grant[]   // type IGrant[]

  interface IGrant {
    attributes: string[];          // required
    possession?: 'own' | 'any';    // optional; omitted ⇒ 'any' (no ownership gate)
    condition?: ConditionJSON;     // optional: declarative tree or { fn, args }
  }
  ```
  - **Fully JSON-serializable** (DB/JSONB) — conditions are declarative trees;
    custom logic is a `{ fn, args }` *reference* (function lives in the registry).
    Inline JS in `.where(fn)` is allowed but opts out of serializability.
  - **`possession` is optional** and out of the key. Omitted ⇒ `any`. `'own'` is
    named sugar the engine expands to the ownership condition (§5.7). Custom
    actions (§6) simply omit it.
  - Naming: type is **`Grant`** (you author `Grant`s; you query `Permission`s).
    `IGrantsListItem` (flat-row form) becomes the flattened projection of `IGrant`.
  - **Resolution:** collect rules for `[resource][action]` across flattened roles;
    a rule *matches* when its `condition` passes (if any) **and** its possession
    is satisfied (`any`/omitted satisfies own- and any-queries; `own` satisfies
    own-queries only, and only if ownership holds). `attributes` = `NotationGlob.
    union` of all matching rules.
- ✅ **Two constructor buckets** — `policy` (engine behavior) vs `context` (data
  conditions read). Rule of thumb: *if a condition reads it with `$.`, it's
  `context`; if the engine reads it to decide behavior, it's `policy`.*
  📌 **Docs:** this rule of thumb must land verbatim in the README/docs.
  ```js
  new AccessControl(grants, {
    policy:  { strictChecks: true, ownerField: 'authorId' /* or owner(ctx) */ },
    context: { region: 'eu', env: 'prod', tz: 'Europe/Istanbul' }
  });
  ```
  - `policy` — **constructor-only**; scope = **everything the engine reads** (not
    just access-decision behavior — also syntax settings): `strict` (§6b),
    `ownerField`/`owner` (§5.7), `pathPrefix` (default `'$'`, §5.2), optional
    `actions`/`resources` allow-lists (§6). Deliberately **no third bucket** for
    one-off settings. (Umbrella could be named `options` instead of `policy`;
    keeping `policy`.)
  - `context` — ambient **data**; set in constructor (defaults) **and per check**
    (`can(role, context)` / `.with()`), merged, per-check wins. `$.`-readable.
    `tz` lives here (reserved, `$.`-readable, per-check overridable). See §5.4b.

### 5.1 Authoring & API
- ✅ `.where(condition)` authors the condition on a grant; `.with(context)`
  supplies context on the check side. Two W's: `where` = *whether* the grant
  applies; attributes (`['*','!password']`) = *what fields* come back.
  ```js
  ac.grant('manager')
    .where('$.order.value > 100000')
    .updateAny('order', ['*']);

  ac.can('manager', { user, order }).updateAny('order').granted;
  // fluent equivalent: ac.can('manager').update('order').with({ user, order })
  ```

### 5.2 Condition format (string sugar → canonical JSON)
- ✅ **String sugar in, canonical JSON out** (the stored form for JSONB/DB).
  ```js
  { and: [ '$.order.value > 100000', '$.user.id != $.order.creatorId' ] }
  // compiles to:
  { and: [ ['$.order.value', '>', 100000], ['$.user.id', '!=', '$.order.creatorId'] ] }
  ```
- ✅ **Node discriminator:** an **array** `[lhs, op, rhs]` is a comparison *leaf*;
  an **object** `{ and|or|not: … }` is a *combinator*. No ambiguity for the evaluator.
- ✅ **Operands — path vs literal:**
  - `'$.…'`-prefixed → notation path resolved from `context` (reuse `notation`
    getter).
  - number → number literal; `true`/`false`/`null` → those literals; other
    bareword/quoted → string literal. **Quotes optional**
    (`endsWith .pdf` == `endsWith ".pdf"`); use quotes to include spaces/commas/`]`
    or to force string type (`"100"` = string vs `100` = number).
  - ✅ Edge case resolved: the path sentinel is **configurable** via
    `policy.pathPrefix` (default `'$'`). Data with `$.`-leading literals just sets
    a different prefix (e.g. `'@'` → paths are `@.order.value`, `$.foo` is literal).

### 5.3 Operators (locked)
- ✅ **Combinators:** `and`, `or`, `not`. `not` is also a generic **modifier** in
  string sugar that compiles to a `not` wrapper around a leaf — keeps the operator
  set small and `not` one concept:
  ```
  '$.now not between [09:00,17:00]' → { not: ['$.now','between',['09:00','17:00']] }
  '$.file.name not startsWith report_' → { not: ['$.file.name','startsWith','report_'] }
  ```
- ✅ **Comparison:** `==`, `!=`, `>`, `>=`, `<`, `<=` (symbol form kept in compiled
  triples — one representation, no `gt` mapping). `!=` stays its own leaf.
- ✅ **Membership:** `in`, `contains`. `nin` **dropped** (use `not … in`).
- ✅ **String:** `matches` (regex), `startsWith`, `endsWith`.
- ✅ **Time:** `before`, `after`, `between`.
- ✅ **`between` semantics:** inclusive **both ends** (like SQL).
  - numbers / dates: `start > end` is a mistake → **throw at compile/validation**.
  - time-of-day (`HH:MM` shape): `start > end` = **overnight wrapping window**
    (`[21:00,03:00]` = 21:00–23:59 ∪ 00:00–03:00).
- ✅ **Network:** IPs fold into `in` — `'$.ip in [10.0.0.0/8, 192.168.1.1]'`.
  Classification uses the **rhs** (static): if any rhs element is CIDR (`/`) or
  IP-shaped, `in` runs IP-membership; this is decided at **compile time** (so a
  malformed CIDR throws when authored, not silently at check time). **`cidr` kept
  as an explicit alias** for the single-range case.

### 5.4 Context & `$.now`
- ✅ `now` is **auto-injected** (defaults to current time; override per check for
  tests). The engine expands it into derived fields (computed in the configured
  timezone):

  | field | example | accepts |
  |---|---|---|
  | `weekday` | `fri` | `fri` / `friday` / `dow` 0–6 |
  | `month` | `mar` | `mar` / `march` / 1–12 |
  | `year` | `2027` | number |
  | `day` | `19` | day of month 1–31 |
  | `date` | `2026-06-19` | YYYY-MM-DD |
  | `time` | `14:30` | HH:MM (wrapping `between`) |
  | `hour` | `14` | 0–23 |
  | `minute` | `30` | 0–59 |

  Weekday/month accept short name, long name (case-insensitive), or number.
  ```js
  // Manager can read reports on Fridays, 09:00–17:00
  ac.grant('manager')
    .where({ and: [ '$.now.weekday == fri', '$.now.time between [09:00,17:00]' ] })
    .readAny('report', ['*']);
  ```

### 5.4b Context sources & the ambient `context` bag
- ✅ **One unified `context` bag.** Set globally on the constructor, extended /
  overridden per check (`.with()` / 2nd arg of `can`), **merged with per-check
  winning**. Any custom key is reachable by notation path (`appId` → `$.appId`,
  `tenant.plan` → `$.tenant.plan`).
  ```js
  const ac = new AccessControl(grants, {
    context: { tz: 'Europe/Istanbul', region: 'eu', env: 'prod', appId: 5 }
  });
  ac.can('manager', { user, appId: 10 })   // per-check overrides appId → 10
    .where({ or: ['$.appId != 10'] });
  ```
- ✅ **Three context sources:**
  1. **Query metadata** — engine-injected, free: `$.role`, `$.roles`,
     `$.resource`, `$.action`, `$.possession`. Most useful in global/resource
     policies (within a normal grant they're partly redundant — the grant is
     already scoped). e.g. "no deletes on Fridays":
     `{ or: ['$.action != delete', '$.now.weekday != fri'] }`.
  2. **Ambient/global** — set once in `context`: `$.tz`, `$.region`, `$.env`,
     `$.appVersion`, `$.featureFlags.*`, etc. (`$.env` is explicit, **not**
     auto-scraped from `process.env` — leakage risk.)
  3. **Per-check caller data** — the bulk: `user`, `order`, `ip`, … via `.with()`.
- ✅ **Reserved keys:** `now`, `tz` (engine reads them; `$.now` is auto-injected,
  see §5.4), and query metadata `role`/`resource`/`action`/`possession`.
- ✅ **Security:** query metadata is injected **after** merge and **wins** over
  caller-supplied context, so a caller can't spoof what they're checking.
  `now`/`tz` remain caller-overridable (useful for tests); query metadata is not.

### 5.5 Custom business logic & async
- ✅ Registry: `ac.defineCondition(name, (ctx, args) => …)`, referenced in a grant
  as `{ fn: name, args: {…} }` — name+args stay JSON-serializable (fits JSONB);
  the function lives in code.
- ✅ **Async path:** `.granted` stays sync for declarative-only conditions;
  `await perm.grantedAsync` (or `ac.checkAsync(...)`) evaluates async/custom
  conditions (DB/IP lookups). *(notes: "Async permission check")*

### 5.6 Resolution & inheritance (LOCKED)
Confirmed by author. *(issue #34 — explicit `deny` must restrict inherited grants.)*
- ✅ **Resolution algorithm** for a check `(role(s), resource, action, possession,
  context)`:
  1. Collect all rules (grants **and** denies) for `(resource, action)` across the
     flattened hierarchy.
  2. **Applicability filter** — drop any rule whose `condition` fails or whose
     possession isn't satisfied. *(this is where failed conditions fold in: a
     failed rule contributes nothing and shadows nothing.)*
  3. `allowed = union(applicable grant attrs)`; `denied = union(applicable deny attrs)`.
  4. `effective = allowed − denied` (**deny wins**).
  5. `granted` = `effective` has ≥1 non-negated attribute.

  Order-independent (union − union), unlike sequential allow/deny lists.
- ✅ **(1) Deny-overrides, not tier-replace.** Grants are purely **additive**;
  inherited perms are reduced only with `deny`. A *smaller child grant does NOT
  reduce* an inherited grant (union wins) — to restrict, you `deny`.
- ✅ **(2) Deny doesn't cascade across possession.** Grants cascade down
  (`any`⊇`own`); denies don't. So `deny create:any` still leaves `create:own`
  (the #34 case).
- ✅ **(3) Multi-role deny scope = per-chain, then union.** Resolve each queried
  role's own inheritance chain (allow − deny), then union across roles. One role's
  deny stays in its own chain and never suppresses another role's grant.
- ✅ **(4) Async safety.** If any applicable rule has an async condition, sync
  `.granted` **throws** ("use grantedAsync"); `grantedAsync`/`checkAsync` resolves.
- 📌 **Docs (must be brief, no complexity):**
  - "To **add** access, grant. To **take away** access, deny. Deny always wins."
  - "A child role can't shrink an inherited grant by granting less — use `deny`."
  - "`deny create:any` still lets `create:own` through."
  - Worked examples to adapt: N1–N4 (additive inheritance, #34 deny, conditional
    add, conditional deny) + gotcha E1 (grants can't reduce — use deny).

### 5.6b Open implementation questions
- ✅ None remaining. (The `$.`-literal edge case is resolved via
  `policy.pathPrefix`, see §5.2.)

### 5.7 Possession (`own`/`any`) backed by the conditions engine
Resolves the long-standing confusion (issue #14): today `readOwn` only selects an
attribute set and **signals intent** — the actual ownership check
(`record.ownerId === user.id`) is left to the consumer, who often misreads `own`
as something the library enforces.
- ✅ **`own` becomes a built-in condition the engine can enforce**, not a
  consumer responsibility. Conceptually `own ≡ '$.user.id == $.resource.ownerId'`.
- ✅ Keep `own`/`any` as **ergonomic sugar** (familiar vocabulary, no API churn);
  `.readOwn(res)` compiles to `read` + the ownership condition.
- ✅ Configurable ownership resolver in the **`policy` bucket** (§5.0):
  ```js
  const ac = new AccessControl(grants, {
    policy: {
      ownerField: 'ownerId',                       // convention, or:
      // owner: (ctx) => ctx.user.id === ctx.resource.ownerId
    }
  });
  ```
  When the check is given the resource in context, the engine **verifies
  ownership itself**.
- ✅ **Ownership enforced _only when configured_ (option b, author-confirmed).**
  Precedence: `owner(ctx)` resolver wins; else the `ownerField` convention
  (`context.user.id === context.<resource>[ownerField]`); the record is supplied
  in the check context keyed by its resource name. **If neither is configured,
  `own` is not gated** — it resolves on the own attribute set (v2), so existing
  code keeps working. (`$.resource` stays the resource *name* metadata; the
  record lives at `$.<resourceName>`.)
- ✅ **`policy.strict.checks`** (part of the unified `strict` option, §6b)
  governs the **resolver-configured-but-unverifiable** case (record/owner
  missing):
  - `true` (**default**) → `own` permission **denied** (`granted:false`).
    Secure-by-default once you've told it how ownership works.
  - `false` → **v2 behavior**: resolves on the `own` attribute set; ownership
    left to the consumer. Opt-in escape hatch.
  - 📌 **DOCS (must emphasize):** make this two-part behavior loud — (1) with no
    resolver, `own` is *not* enforced (no silent lock-down of existing apps);
    (2) once `ownerField`/`owner` is set, a missing record under default strict
    **denies**. State the precedence and where the record is read from.
- ✅ **Bare verbs stay v2-consistent:** `.update()` ≡ `.updateAny()` at **both**
  grant and check time (no asymmetry / no surprise). The "can this user act on
  **this record**" question is `.updateOwn(res, { user, resource })`, which — via
  the `any ⊇ own` cascade (§5.6) — is granted if they have blanket `any` **or**
  they own the record. (No "smart bare method"; that idea was dropped.)
- ✅ Only v3 change to `Own` checks: `.updateOwn()` now **enforces** ownership
  (was: just returned the own attribute set; `any` holders still pass via cascade,
  exactly as v2).
- ✅ The `any`→`own` union fallback stays as pure resolution behavior, independent
  of this.
- ✅ Possession `other` ("any not-owned") is therefore redundant — it's just
  `any && not own`. **Dropped** (removed from §7).
- ✅ **README/docs blurb (publish with the feature) — brief & prominent:**
  > **Ownership is now enforced.** In v2, `readOwn`/`updateOwn`/… only chose
  > *which attributes* a user could access — confirming the record actually
  > belonged to them was left to your code. In v3, AccessControl enforces it.
  > Tell it how ownership is determined once (`ownerField: 'authorId'` or an
  > `owner(ctx)` function), pass the record in the check context, and `own`
  > permissions are granted only when the record belongs to the requester — no
  > more manual `record.ownerId === user.id` checks.

## 6. Custom (non-CRUD) actions — *(issue #87)* (LOCKED)
Storage already supports this: §5.0 made the action the **key** and `possession` an
optional **field**, so a custom action needs no shape change:
```js
grants.editor.article.publish = [ { attributes: ['*'], possession: 'own' } ]
```
- ✅ **Generic method `.action(actionSpec, resource?, attributes?)`** authors/checks
  any action; CRUD verbs become named sugar over it. `actionSpec` carries optional
  possession via the `:own`/`:any` convention (omit ⇒ `any`).
  ```js
  ac.grant('editor').action('publish', 'article', ['*']);       // publish (any)
  ac.grant('author').action('publish:own', 'article', ['*']);   // ownership-gated
  ac.can('author', { user, article }).action('publish:own', 'article').granted;
  ```
- ✅ **`.do()` is the single sanctioned alias** of `.action()` (the one intentional
  exception to the §2 alias purge). Generic — CRUD *and* custom:
  `ac.can('admin').do('update')` / `ac.can('admin').do('publish','article')`.
- ✅ **CRUD methods unchanged for users**, reimplemented over the generic path:
  `.createAny(res,attrs)` → `.action('create:any',res,attrs)`, `.create()` →
  `.action('create:any',…)`, `.updateOwn(...)` → `.action('update:own',...)`. So
  `.update('post')` ≡ `.action('update','post')` ≡ `.do('update','post')`.
- ✅ **Possession applies uniformly** — omit ⇒ `any`; `:own` is ownership-gated via
  the same `ownerField`/`owner` resolver. All §5.6 resolution rules carry over
  (e.g. `publish:any` satisfies a `publish:own` query; `deny publish:any` leaves
  `publish:own`; `.where()` conditions work identically).
- ✅ **Validation:** drop the CRUD-only check in `normalizeActionPossession`; any
  valid name is a permitted action. `Action` enum stays as CRUD convenience
  constants; action type is `Action | string`. Reserved separator `:` (possession);
  possession part if present must be `own`/`any`.
- ✅ **Optional `strict` typo-protection** (see §6b): when `strict.actions` /
  `strict.resources` is on, an unknown action/resource **throws** instead of
  silently returning `granted:false`. Known set is **derived from the grants**
  (optional explicit `policy.actions`/`policy.resources` lists also accepted).

### 6a. Name validation (roles, resources, actions — uniform) (LOCKED — revised)
Applied to **all** names (roles, resources, actions) as one documentable rule.
**Case-preserving, non-magical** (revised away from the earlier lowercase/flatten
rule, which destroyed camelCase and rejected kebab-case):
- **trim ends; preserve case** (`bulkExport` stays; `Admin` ≠ `admin`, the author's
  responsibility — like any identifier).
- charset **`[A-Za-z0-9_-]`** → supports camelCase, kebab-case, snake_case; rejects
  internal spaces, `.`, and other punctuation with a clear error.
- **Reserved separators** (excluded by the charset): `/` group/category (§7),
  `:` action/possession (§6). `.` is **not** a name char (avoids collision with
  the `notation` attribute/condition path syntax).
- Reserved keywords `*` / `!` / `$` / `$extend` (also excluded by the charset).
```
bulkExport → bulkExport   post-docs → post-docs   my_role → my_role   Admin → Admin
"send mail" → ERROR (space)   post.docs → ERROR (dot)   media/photo → ERROR in P1
  (in P6, '/' is split first: group 'media' + 'photo')   publish:own → action+possession
```
Rationale: closest to v2 (case-sensitive, minimal), but with a safe charset and the
two v3 separators reserved. No lowercasing ⇒ no `Admin`/`admin` silent merge.

### 6b. `strict` option (LOCKED) — supersedes standalone `strictChecks`
`policy.strict` is a **boolean OR object**:
```js
policy: { strict: true }                                  // all on
policy: { strict: { checks: true, actions: true, resources: false, roles: true } }
```
- Keys: `checks` (ownership, §5.7), `roles`, `actions`, `resources`.
- **Defaults:** `checks: true`, `roles: true`, `actions: false`, `resources: false`.
  (`checks`/`roles` default on = secure + matches today's throw-on-unknown-role;
  `actions`/`resources` fail-closed/lenient by default — flip on for loud typos.)
- `strict: true` → all on; `strict: false` → all lenient.

## 7. Scope decisions
- ✅ Events & audit hooks — see §7.3. *(notes lines 43, 78)*

### 7.1 Role groups & resource categories via `/` (LOCKED)
Naming: **roles have _groups_; resources have _categories_.** One `/` convention:
`admins/moderator` → group `admins` + role `moderator`; `media/photo` → category
`media` + resource `photo`. (`/` is a reserved separator, §6a.)
- ✅ **`setup()` declares the _vocabulary_** (roles, groups, resources, categories,
  actions); `grant()` declares _permissions_. Format #1 (object; `_` = ungrouped,
  reserved so it can't be a group/category name):
  ```ts
  ac.setup({
    roles:     { admins: ['admin','moderator'], _: ['user','viewer'] },
    resources: { media: ['photo','video'], _: ['profile'] },
    actions:   ['publish','approve'],   // optional, feeds strict.actions
  }); // chainable
  ```
  With `strict.roles`/`strict.resources` on, anything not declared here **throws**
  (typos in a group/category or member caught loudly).
- ✅ **What groups/categories buy you** (not cosmetic):
  1. **Bounded bulk grants** — the safe replacement for the declined `*` wildcard
     (#58): `ac.grant('admins').readAny('media')` hits every member × every member,
     but the blast radius is the explicit set from `setup()`, not unbounded.
  2. **Dynamic shared base** — grant-to-group resolves at check time: members
     **inherit** the group's grants (group = implicit flat `$extend`). Add a role
     to a group later → it instantly gains the grants. Deny-overrides (§5.6) still
     lets a member carve back. *(chosen over expand-at-grant-time, which is static.)*
  3. **Category-level policy** via `require()` (§7.2) — cross-cutting gates.
  4. **Introspection/management & namespacing**: `ac.group('admins').getRoles()`,
     `ac.category('media').getResources()`, `ac.removeGroup(...)`; and
     `media/photo` ≠ `legal/photo` (no collisions). Makes `strict` meaningful.
- 📌 **Docs:** lead with *"`setup()` declares your vocabulary; `grant()` declares
  permissions."* and frame groups as **bounded wildcards** (the safe `*`).
- Open: single-level grouping only for v3 (nesting `a/b/c` deferred).

### 7.2 `require()` — mandatory restriction gates (LOCKED, resolves resource-level policy)
Two distinct verbs, two intents (do not conflate):
- **`.where(cond)` = conditional _grant_** — scopes a permission; can only **add**
  access under a condition. *(§5.1)*
- **`.require(cond)` = mandatory _restriction_** — independent of grants; a gate
  that must pass for access to a scope; can only **restrict**, never grant.
- ✅ Three scopes, one verb:
  ```ts
  ac.require('$.env == prod');                        // global (every check)
  ac.category('billing').require('$.ip cidr 10.0.0.0/8');   // category gate
  ac.resource('billing/invoice').require('$.now.time between [09:00,18:00]'); // one resource
  ```
- ✅ **Resolution:** `granted = (a grant matches, §5.6) AND (every applicable
  require-gate passes)`. Because `require()` can only subtract, adding one can
  never widen access — easy to reason about for security. 📌 put this property in docs.
- ✅ Same condition format/engine as `.where()` (string sugar → JSON, §5.2).
- ✅ **Resolves** the former §7 "resource-level policy + global policy in
  constructor" item — it was always `require()` at resource/category/global scope.

### 7.3 Events & audit hooks (LOCKED)
Observational event system; doubles as the audit log. `ac.on(name, cb)` /
`ac.off` / `ac.once`; name accepts the string or the enum (values are the strings).
```ts
enum AccessControlEvent { Access = 'access', Change = 'change', Error = 'error' }
ac.on('access', e => audit(e));
ac.on(AccessControlEvent.Change, e => …);
```
- ✅ **Three events:**
  - `access` — every check resolved (granted **and** denied). This *is* the access
    audit log.
  - `change` — grants/vocabulary mutated (policy-edit audit): `grant`/`deny`/
    `extend`/`remove`/`setGrants`/`reset`/`setup`/`require`/`lock` (one event, a
    `type` discriminator; `lock` folded in here — no 4th event).
  - `error` — a check/op threw (unknown role under `strict`, custom condition fn
    rejected, async failure).
- ✅ **Envelope (all events):** `{ name, timestamp }`. *(`name`, not `event`.)*
- ✅ **`access` payload** (the audit record):
  ```ts
  { name:'access', timestamp, roles:string[], resource:string, category?:string,
    action:string, possession?:'own'|'any', granted:boolean, attributes:string[],
    reason?:'no-grant'|'condition-failed'|'require-failed'|'ownership-failed'|'strict',
    context?:object }   // context included (⚠️ PII lives here — document)
  ```
  `reason` makes denials debuggable/explainable.
- ✅ **`change` payload:** `{ name:'change', timestamp, type, detail }`.
- ✅ **`error` payload:** `{ name:'error', timestamp, error:AccessControlError,
  operation, roles?, resource?, action? }` (reuses §4 structured error fields).
- ✅ **Guardrails:** tiny **internal** emitter (no Node `EventEmitter` dep —
  ESM/browser-safe, keep single-dep footprint); **zero overhead when no listener**;
  **observational only** (listeners cannot veto/alter a decision — deciding is
  `where()`/`require()`'s job); **fire-and-forget** (listeners not awaited; a
  throwing listener is caught/isolated, never breaks the check).

### 7.x Earlier scope items (resolved)
- ✅ Possession `other` ("any not-owned"): **dropped** — redundant once `own` is
  a condition; it's just `any && not own` (see §5.7). *(notes line 29)*
- ✅ Resource-level / global policy: **resolved via `require()`** (§7.2).
  *(notes lines 30, 76)*
- ✅ Bulk/wildcard granting (`*` role/resource): **not supported** — data-leak
  footgun; superseded by **bounded group/category bulk grants** (§7.1). *(issue #58)*

## 8. Docs deliverables (LOCKED — write when API is final)
- ✅ **`MIGRATION.md` — v2 → v3 guide.** Side-by-side "same result in v3" mapping
  (alias removal, `action:possession` storage→field, `getGrants` frozen copies,
  enforced `own`/`strict`, lowercased names, deny-overrides, etc.). **Banner at
  top *and* bottom:** *"✨ See what you can do **more** with v3 →"* linking to
  `WHATS-NEW.md`.
- ✅ **`WHATS-NEW.md` — new capabilities.** Conditions/`.where()` + `.with()`,
  enforced ownership, custom actions (`.action()`/`.do()`), deny-overrides,
  `strict`, `policy`/`context`, `$.now.*`, async checks. Links back to `MIGRATION.md`.
- ✅ Both absorb the scattered **📌 Docs** blurbs already in this roadmap:
  policy-vs-context rule of thumb (§5.0), enforced-ownership blurb (§5.7),
  deny-overrides one-liners (§5.6).
- ✅ **`examples/` folder** — keep runnable reference materials, kept in sync as the
  API lands: SQL schema (`accesscontrol-v3-schema.sql`), `grantsObject` +
  equivalent `grantsList` (`accesscontrol-v3-grants.example.ts`), and an Express
  integration example (middleware). Seeded now; expand during implementation.

## 9. Implementation sequence (tick off as done)
Dependency-ordered. The conditions engine (Phase 3) is the spine; possession,
`require`, and strict build on it. Docs are last (§8) so late changes don't churn them.
- [x] **P0 — Tooling/scaffold:** ESM build, `biome-config-oy`, `tsconfig-oy`@2,
  vitest + coverage, Stryker (`npm run mutation`, break 85; baseline 79.4% to lift
  as tests are rewritten); split `src/utils.ts` into modules
  (`generic`/`validation`/`roles`/`grants`/`notation`/`lock`) behind a barrel. *(§1, §4)*
- [x] **P1 — Core model:** new `Grant` shape (`IGrant[]`, possession field,
  optional condition), name normalization (Option 1: case-preserving,
  `[A-Za-z0-9_-]`), structured `AccessControlError`, immutable getters, alias
  purge, `$extend` in list form (inheritance rows). *(§2, §3, §4, §5.0, §6a)*
  Note: `.action()`/`.do()` is P5. Re-granting the same possession+effect+
  condition replaces (last-write-wins); different conditions coexist.
- [x] **P2 — Resolution engine:** deny-overrides (allow ∪ − deny ∪, glob-aware
  via negate+normalize), per-chain then union across roles, `any⊇own` cascade
  (deny strict, no cascade), `!password`⇒`*` (negation-only ⇒ implied `*`).
  Conditions stored but not yet evaluated (P3). *(§3, §5.6)*
- [x] **P3 — Conditions engine:** string-sugar→JSON compiler, operators,
  evaluator, `policy`/`context` buckets, `$.now.*`, `pathPrefix` (sync). *(§5.1–5.4)*
  Authored via `.where()`; context via `.with()` / `can(role, ctx)` /
  `check({ context })`; folded into the §5.6 applicability filter; query metadata
  wins over caller context. Custom-fn `{ fn }` deferred to P8 (throws on sync
  eval). Bareword `true`/`false`/`null` compile to those literals (quote to force
  string); numbers auto-convert.
- [x] **P4 — Possession & ownership:** engine-enforced `own` via `ownerField`/
  `owner(ctx)` (owner wins), record-aware `Own` checks, `any ⊇ own` cascade.
  `strict.checks` (default true) governs the resolver-configured-but-unverifiable
  case; **no resolver ⇒ `own` not gated (v2, option b)**. *(§5.7)*
- [x] **P5 — Custom actions & strict:** `.action()`/`.do()` generic entry (CRUD
  becomes sugar over the same commit/check path); any valid name is an action
  (CRUD-only validation dropped). Unified `policy.strict` (boolean | object):
  `checks`/`roles` default on, `actions`/`resources` default off; throws on
  unknown action/resource/role at check time. Known sets derived from grants
  (+ CRUD, + `policy.actions`/`policy.resources`). *(§6, §6b)*
- [x] **P6 — Groups & categories:** `/` qualifies `group/role` & `category/resource`
  (single level); group/category grants cascade **dynamically** to members at check
  time (bounded bulk grants; deny-overrides still let a member carve back).
  `setup()` declares vocabulary (additive, chainable; `_` = ungrouped) and feeds
  the strict known sets; `group()`/`category()`/`getGroups()`/`getCategories()`/
  `removeGroup()`/`removeCategory()` for introspection & management. Resolution
  derives group/category from the name, so `setup()` is the safety/strict layer,
  not a prerequisite. *(§7.1)*
- [x] **P7 — `require()` gates:** mandatory restrictions at global (`ac.require`),
  category (`ac.category(c).require`) and resource (`ac.resource(r).require`)
  scope. `granted = (a grant matches) AND (every applicable gate passes)`; gates
  can only restrict, never grant. Same condition engine as `.where()`; compiled
  on add. `getRequirements()` for inspection/serialization. *(§7.2)*
- [x] **P8 — Async checks:** `ac.defineCondition(name, fn)` registry + `{ fn, args }`
  conditions (in `.where()` and `require()`); `perm.grantedAsync` / `ac.checkAsync()`
  await custom/async fns. Sync `.granted` resolves eagerly and **throws
  `asyncRequired`** when an applicable rule/gate carries a custom fn; the async
  path memoizes so sync accessors work afterwards. Resolution refactored to share
  one core between sync/async (`prepareResolution`/`collectRoleResolution`/
  `applyRule`). *(§5.5/§5.6.4)*
- [x] **P9 — Events:** tiny internal `Emitter` (no Node dep); `ac.on`/`once`/`off`
  (string or `AccessControlEvent` enum). `access` (every resolved check — audit,
  with denial `reason`), `change` (grant/deny/extend/remove/setGrants/reset/setup/
  require/lock), `error` (a check threw). Observational-only, listener-isolated,
  fire-and-forget, zero overhead when no listener. *(§7.3)*
- [x] **P10 — DB serialization:** `getGrantsList()` (inverse of `getGrants()`):
  flat DB-friendly rows + `{ role, $extend }` inheritance rows, round-tripping
  identically (object⇄list, both accepted as input). `getRequirements()` exports
  compiled gates by scope. *(§5.0, this section's SQL)*
- [x] **P11 — Docs (LAST):** `WHATS-NEW.md` (v3 capabilities), `MIGRATION.md`
  (v2→v3, with the ✨ banners), v3 README rewrite, and an Express middleware
  example (`examples/express-middleware.example.ts`) alongside the seeded SQL +
  grants examples. *(§8)*

## References
- Notes: uploaded `accesscontrolnotes.md`.
- Issues: #25 (aliases), #34 (inheritance override), #35 (conditions),
  #58 (wildcards — declined), #87 (custom actions).
- Prior art for ideas (do not copy wholesale): ory/ladon, YLuchaninov/PolicyLine,
  tensult/role-acl, nestjs-community/nest-access-control.
