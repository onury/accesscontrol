# AccessControl - Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/) and this project adheres to [Semantic Versioning](http://semver.org).


## 3.0.1 (2026-06-25)

### Added
- **`===` / `!==` condition operators.** Accepted as aliases for `==` / `!=`
  (which are already **strict** — value *and* type, no coercion). They're
  normalized to the canonical operator at compile time, so stored/serialized
  conditions are unchanged.

### Docs
- Quote string literals in condition examples and document operand **type
  inference**: a literal's type comes from how it's written (`100` is a number,
  `"100"` a string), so quote any value that could be misread as a
  number / `true`/`false`/`null` / `$.path`.


## 3.0.0 (2026-06-14)

The release that turns AccessControl from RBAC-with-attribute-filtering into a
full **policy engine** — landing the capabilities most requested since v2:
attribute conditions (ABAC), real ownership enforcement, custom (non-CRUD)
actions, deny-overrides, mandatory restriction gates, role groups & resource
categories, async checks, an audit event stream, one-call serialization, and a
hardened authorization path. The everyday API (`grant`/`deny`, `can`,
`createAny`/`readOwn`/…, `permission.granted` / `.attributes` / `.filter()`) is
unchanged — see [MIGRATION](./docs/MIGRATION.md) for the few breaking points and
[WHATS-NEW](./docs/WHATS-NEW.md) for worked examples.

### Added
- **Conditions (ABAC) — `.where()`.** Attach a declarative condition that decides
  whether a grant applies at check time, written as readable string sugar or
  canonical JSON. Operators: `==` `!=` `>` `>=` `<` `<=`, `in`, `contains`,
  `matches`, `startsWith`, `endsWith`, `before` / `after` / `between`, and `cidr`;
  combine with `{ and, or, not }`. The time helper `$.now.*` is auto-injected
  (overridable for deterministic tests). (fixes [#35](https://github.com/onury/accesscontrol/issues/35), [#41](https://github.com/onury/accesscontrol/issues/41))
- **Per-check context.** Supply condition data via `can(role, context)`, the
  fluent `.with(context)`, or `check({ context })`; ambient defaults via
  `new AccessControl(grants, { context })`.
- **Object-form checks — `check()` / `checkAsync()`.** Resolve an `IQueryInfo`
  (`{ role, resource, action, context }`) straight to a `Permission` — the
  programmatic alternative to the fluent `can(...).readAny(...)` chain.
- **Permission result** carries `granted` / `grantedAsync`, `attributes`,
  `roles`, `resource`, `action`, `possession` (the *resolved* possession — `any`
  when an `own` query is satisfied via an `any` grant), and `filter(data)` to
  strip a payload (object **or array of objects**) to the allowed attributes.
  (fixes [#23](https://github.com/onury/accesscontrol/issues/23), [#36](https://github.com/onury/accesscontrol/issues/36))
- **Enforced ownership.** `own` permissions now actually verify the record belongs
  to the requester. Configure once with `policy.ownerField` or a custom
  `policy.owner(ctx)` resolver; backward-compatible (with no resolver configured,
  `own` keeps v2 behavior). A blanket `any` grant still satisfies `own` via the
  cascade. (fixes [#14](https://github.com/onury/accesscontrol/issues/14), [#24](https://github.com/onury/accesscontrol/issues/24))
- **Custom (non-CRUD) actions — `.action()` / `.do()`.** Any action name works
  with the full possession / ownership / condition machinery (e.g.
  `action('publish:own', 'article')`). `.do()` is the one sanctioned alias and
  also covers CRUD. (fixes [#87](https://github.com/onury/accesscontrol/issues/87), [#46](https://github.com/onury/accesscontrol/issues/46))
- **Mandatory gates — `.require()`.** Independent restriction gates that can only
  narrow access: `granted = (a grant matches) AND (every applicable gate passes)`.
  Scoped globally, per `category()`, or per `resource()`. Exported/imported via
  `getRequirements()`.
- **Role groups & resource categories (`/`).** Declare a vocabulary with
  `setup({ roles, resources, actions })`, then grant to a group or category once
  and reach every member dynamically — a bounded, collision-free alternative to
  `*` (`media/photo ≠ legal/photo`). Introspect with `group()`, `category()`,
  `getGroups()`, `getCategories()`, `getVocabulary()`; manage with `removeGroup()`,
  `removeCategory()`. (fixes [#58](https://github.com/onury/accesscontrol/issues/58), [#103](https://github.com/onury/accesscontrol/issues/103))
- **Async checks & custom functions.** Register logic with
  `defineCondition(name, fn)` and reference it from a grant or gate as
  `{ fn, args }` (stays JSON-serializable). Resolve via `grantedAsync` /
  `checkAsync`; declarative checks stay synchronous.
- **Events & audit hooks.** A built-in, dependency-free emitter: `access` fires on
  every resolved check (granted *and* denied, with a denial `reason`), `change`
  tracks policy edits, `error` reports faults. Listeners are observational and
  isolated — a throwing listener never breaks a check. `on()` / `off()` /
  `once()`, with the `AccessControlEvent` enum.
- **One-call serialization — `snapshot()` / `restore()`.** `snapshot()` captures
  grants + gates + vocabulary as one plain-JSON object; `restore()` rebuilds the
  model exactly (a full replace through the validated `setGrants()` / `setup()` /
  `require()` paths). Survives `JSON.stringify` / a `JSONB` column.
- **Serialization primitives.** `getGrantsList()` (DB-friendly flat rows) ⇄
  `getGrants()` (object form), `getRequirements()` (gates), and `getVocabulary()`
  (the `setup()` input). The constructor accepts both object and list forms.
- **Structured options — `new AccessControl(grants, { engine, policy, context })`.**
  Three buckets: **`engine`** (mechanics & security — `pathPrefix`, `allowRegex`,
  `charset`, `safeErrors`), **`policy`** (your model — `ownerField` / `owner`,
  `strict` with `roles` / `checks` / `actions` / `resources` switches, plus
  action & resource allow-lists), and **`context`** (ambient condition data).
- **Policy lifecycle — `lock()` / `reset()`.** Freeze a finalized model against
  further edits, or clear it for a clean rebuild.
- **Introspection & management.** `getActions()` (all actions, or scoped to a
  role incl. inherited — fixes [#33](https://github.com/onury/accesscontrol/issues/33)),
  `getGroups()` / `getCategories()`, `hasGroup()` / `hasCategory()` / `hasRole()` /
  `hasResource()`, `getInheritedRolesOf()`, `removeGroup()` / `removeCategory()` /
  `removeRoles()` / `removeResources()`.
- **New named exports.** `Charset`, `ErrorCode`, `AccessControlEvent`, and the
  `AccessControlError` class, alongside `Action` / `Possession` — now real enums.
  (fixes [#90](https://github.com/onury/accesscontrol/issues/90))

### Changed
- **Grants model shape.** Possession is now a **field** and each action maps to an
  **array of rules** (`{ possession, attributes, effect?, condition? }`), so a
  single action can carry conditions, deny rules, and multiple coexisting rules —
  none of which the v2 attribute-list value had a slot for. Re-export once
  (`getGrants()` / `getGrantsList()`) to migrate persisted v2 data.
  ```js
  // v2 — possession fused into the key; value is just an attribute list (one rule):
  { user: { post: { 'read:any': ['*'] } } }

  // v3 — action key → array of rules; possession/effect/condition are fields,
  // so this is now representable (and v2 simply could not store it):
  { user: { post: { read: [
    { possession: 'any', attributes: ['*', '!secret'] },
    { possession: 'own', attributes: ['*'], condition: '$.post.status != "locked"' },
    { effect: 'deny', possession: 'any', attributes: ['ssn'] }
  ] } } }
  ```
- **Inheritance in the flat list travels as `$extend` rows**
  (`{ role, $extend: [...] }`). The programmatic `extend()` / `extendRole()` form
  is unchanged.
- **Name handling is case-preserving and charset-validated** (`[A-Za-z0-9_-]`).
  `Admin` and `admin` are now distinct; `:` `/` `$`, spaces and dots are reserved
  and rejected. Opt into international names with `engine.charset: Charset.UNICODE`.
- **`getGrants()` / `getGrantsList()` / `getRequirements()` return frozen deep
  copies.** Mutate the model through the builder API instead.
- **`strict.roles` defaults on** (throws on an unknown role at check time, as v2
  did); set `policy.strict.roles = false` for lenient behavior.

### Removed
- **Breaking**: the default export — use the named `import { AccessControl } from 'accesscontrol'`.
- **Breaking**: static getters (`Action`, `Possession`, `Error`, …) on the
  `AccessControl` class — use the respective named imports.
- **Breaking**: redundant method aliases (`allow()`, `reject()`, `query()`,
  `inherit()`, …), in favor of canonical names — the one intentional alias kept
  is `.do()`. (fixes [#25](https://github.com/onury/accesscontrol/issues/25))

### Fixed
- **Inheritance override / deny-overrides.** An explicit `deny` now restricts
  inherited grants too — deny always wins. Grants are purely additive (a smaller
  child grant no longer shrinks an inherited one); `deny` does not cascade across
  possession (`deny create:any` still leaves `create:own`). (fixes [#34](https://github.com/onury/accesscontrol/issues/34))
- `utils.getUnionAttrsOfRoles()` no longer throws when a (flattened/extended) role
  does not define the queried resource.
- `utils.getCrossExtendingRole()` now returns `null` (instead of `false`) when no
  cross-inheritance is found.

### Security
- **`tryCan()` — fail-closed checks.** Identical to `can()` but never throws: an
  invalid query, a `strict` violation, or a custom/async condition hit on the sync
  path all resolve to `granted: false`. Prefer it on the request path so a thrown
  error can't become an accidental *allow*.
- **`strict.checks` defaults on** — if ownership is configured but the record is
  missing from the context, the check denies (secure by default).
- **Prototype-pollution-safe.** The gadget names `__proto__`, `prototype` and
  `constructor` are rejected; any name colliding with an inherited member
  (`toString`, …) is treated as plain data, never a prototype member.
- **Opt-in, ReDoS-guarded regex.** The `matches` operator is off by default
  (`engine.allowRegex`); when enabled, patterns are screened for catastrophic
  backtracking and condition nesting depth is bounded.
- **Redacted errors with stable codes.** Every `AccessControlError` carries a
  machine-readable `ErrorCode`; `engine.safeErrors` (default on) keeps
  caller-supplied values out of messages (they remain on `err.role` / etc.).
- **ASCII-by-default charset** (homograph-safe), with `Charset.UNICODE` as an
  explicit opt-in.

### Dev & environment
- **(Dev)** **Breaking**: ESM-only and requires **Node.js v20+**; the CommonJS
  build is removed (stay on v2 for CJS).
- **(Dev)** Ships an `exports` map — only the package root (`accesscontrol`) and
  `package.json` are importable; internal paths are no longer reachable.
- **(Dev)** Now built on `notation` v3 (`NotationGlob.union`, `Notation#filter`).
  (fixes [#96](https://github.com/onury/accesscontrol/issues/96))
- **(Dev)** Modernized toolchain: **TypeScript 6**, ESM-only build via `tsc` (no
  bundler), **Vitest** + istanbul coverage (from Jest/ts-jest), **Biome** lint +
  format (from ESLint/TSLint), **GitHub Actions** CI (from Travis), and shared
  config via `tsconfig-oy` / `biome-config-oy`.
- **(Dev)** Runs on **Deno** (`import … from 'npm:accesscontrol'`) and **Bun** in
  addition to Node.js ≥ 20 — a consequence of the pure-ESM, no-Node-builtins
  build. (fixes [#106](https://github.com/onury/accesscontrol/issues/106))


## v2.3.0 (2021-05-10)

### Added
- `IGrants`, `IGrantsItem`, `IGrantsList`, `IGrantsListItem` types.

### Changed
- `coveralls` and `notation` dependencies.

### Fixed
- `package-lock.json` errors.


## v2.2.1 (2018-02-24)

### Fixed
- An issue with attribute filtering caused by the core dependency Notation. Now [fixed](https://github.com/onury/notation/issues/7) and updated.
- **(Dev)** Updated dev-dependencies to latest versions. Removed yarn.


## v2.2.0 (2017-11-25)

**This release greatly improves stability!**

### Fixed
- An issue where action and possession of a permission query is not pre-normalized. Only   `#permission()` method was affected.
- An issue where it would throw even if `$extend` was used properly in the initial grants model, passed to the constructor or `#setGrants()`. Fixes [issue #22](https://github.com/onury/accesscontrol/issues/22).
- A memory leak (leading to "maximum call stack" error) occurs while processing role hierarchy.
- An issue where role validation would incorrectly return `true` in a specific case.

### Changed
- `#lock()` to throw a meaningful error if not successful.
- `#hasRole()` and `#hasResource()` methods to also accept a string array (to check for multiple at once), in addition to `string` (single).
- Various chain methods to throw when explicit invalid values are passed. e.g. `ac.grant()...` will not throw (omitted parameter allowed) but `ac.grant(undefined)...` will throw. This mitigates the chance of passing an unset variable by mistake.
- Various revisions, optimizations and clean-up.
- **(Dev)** Migrated tests to Jest. Refactored tests to TypeScript. Removed Jasmine and dependencies. 
- **(Dev)** Adapted `yarn`. Enabled test coverage via `jest`. Added `coveralls` support.
- **(Dev)** Added moooore tests. Revised code style. Improved coverage.


## v2.0.0 (2017-10-05)

### Changed
- **Breaking**: Cross role inheritance is no more allowed. Fixes [issue #18](https://github.com/onury/accesscontrol/issues/18).
- **Breaking**: Grants model cannot be emptied any more by omitting the parameter (e.g. `#setGrants()`) or passing `null`, `undefined`. This will throw. You need to either, explicitly call `#reset()` or set grants to an empty object (`{}`) in order to reset/empty grants safely. 
- **Breaking**: Renamed `#access()` to `#query()`. This is an alias for `#can()` method.
- `AccessControl` to throw if any reserved keywords are used (i.e. for role, resource names) such as `"$"`, `"$extend"`.

### Fixed
- An issue where deeper inherited roles (more than 1 level) would not be taken into account while querying for permissions. Fixes [issue #17](https://github.com/onury/accesscontrol/issues/17).
- A mutation issue occurred when resource attributes are unioned. ([Notation issue #2][notation-issue-2]).
- An issue with unioned attributes (when a role extends another and attributes (globs) are unioned for querying permissions). Fixes [issue #19](https://github.com/onury/accesscontrol/issues/19) ([Notation issue #3][notation-issue-3]).

### Added
- `AccessControl#lock()` method that freezes the underlying grants model and disables all functionality for modifying it. This is useful when you want to restrict any changes. Any attempts to modify (such as `#setGrants()`, `#grant()`, `#deny()`, etc) will throw after grants are locked. There is no `unlock()` method. It's like you lock the door and swallow the key. :yum:
- `AccessControl#isLocked` `boolean` property.
- `AccessControl#getInheritedRolesOf()` convenience method.
- The ability to detect invalid grants object passed to `AccessControl` instance. In order to prevent silent, future errors and mistakes; `AccessControl` now thoroughly inspects the grants object passed to constructor or `#setGrants()` method; and throws immediately if it has an invalid structure or configuration.
- The ability to parse comma-separated attributes. You can now use this, in addition to string arrays; for defining resource attributes.


## v1.5.4 (2017-09-22)

### Fixed
- An issue where the static method `AccessControl.filter()` does not return the filtered data properly. Fixes [issue #16](https://github.com/onury/accesscontrol/issues/16).


## v1.5.3 (2017-08-25)

### Changed
- Errors are now thrown with more [meaningful messages](https://github.com/onury/accesscontrol/issues/13#issuecomment-324755478).


## v1.5.2 (2017-07-02)

### Fixed
- An issue where the grants were not processed into the inner grants model structure; if an array is passed to `AccessControl` constructor; instead of using `.setGrants()`. Fixes [issue #10](https://github.com/onury/accesscontrol/issues/10).


## v1.5.1 (2017-05-24)

### Fixed
- TS import issue. Use `import { AccessControl } from 'accesscontrol'` in TypeScript projects.


## v1.5.0 (2017-03-08)

### Changed
- Migrated whole code base to TypeScript.
- You could grant permissions for multiple roles at once. Now, you can also grant permissions for multiple resources at the same time. This is very handy when you permit _all attributes_ of the resources; e.g. `ac.grant(['admin', 'superadmin']).readAny(['account', 'video'], ['*'])`. The caveat is that the resources (most probably) have different attributes; so you can either permit all, or only common attributes (e.g. `['id', 'name']`).
- Extending a role with a non-existent role will now throw.

### Added
- More strict validation checks. It will now throw on invalid information passed for both grants and permission checks. This helps prevent typos, unintended permission checks, etc...

### Fixed
- A bug where checking permission with multiple roles would mutate the permission attributes. Fixes [issue #2](https://github.com/onury/accesscontrol/issues/2).
- A mutation issue when an access definition object (`IAccessInfo` instead of role(s)) passed to `.grant()` or `.deny()` methods.


## v1.0.1 (2016-11-09)

### Fixed
- A syntax issue that throws when permission filter is called. Fixes [issue #1](https://github.com/onury/accesscontrol/issues/1).
- (Dev) added filter test.


## v1.0.0 (2016-09-10)

- initial release.


[notation]:https://github.com/onury/notation
[notation-issue-2]:https://github.com/onury/notation/issues/2
[notation-issue-3]:https://github.com/onury/notation/issues/3
