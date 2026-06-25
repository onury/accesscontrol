---
title: Serialization & Databases
description: The two grants shapes (object & flat list) with basic and complex JSON examples, a SQL schema, and how require() gates and setup() vocabulary persist separately.
---

AccessControl is storage‑agnostic and runs in memory. The grants model is plain
JSON in two interchangeable shapes, so you can persist it as a JSONB blob or as
relational rows and rebuild it on boot — the round‑trip is exact.

:::tip[The one‑call way: `snapshot()` ⇄ `restore()`]
A model is three structures (grants, gates, vocabulary). To avoid persisting and
restoring each by hand, [`snapshot()`](#snapshot--restore-the-whole-model-in-one-call)
bundles all three into one JSON object and `restore()` puts it back:

```js
await db.savePolicy(JSON.stringify(ac.snapshot()));          // persist everything
const ac = new AccessControl().restore(await db.loadPolicy()); // restore everything
```

The rest of this page explains the individual pieces — reach for them when you
want relational rows or finer control.
:::

:::note[What lives where]
- **Grants** (role → resource → action rules, incl. conditions & `$extend`) →
  `getGrants()` / `getGrantsList()`, fed back to the constructor.
- **`require()` gates** → `getRequirements()`, a **separate** structure (not part
  of the grants) — [see below](#require-gates-persist-separately).
- **`setup()` vocabulary** (groups, categories, custom actions) →
  `getVocabulary()`; **re‑applied** on restore (needed for `strict` and
  introspection, not for plain resolution).
- **All three at once** → `snapshot()` / `restore()`.
:::

## The Two Grants Shapes

### Object Form (Canonical, Readable)

`grants[role][resource][action]` is an **array** of rules
(`{ attributes, possession?, condition?, effect? }`). Possession omitted ⇒
`any`; effect omitted ⇒ `grant`.

```json
{
  "user": {
    "post": {
      "read": [{ "possession": "any", "attributes": ["*", "!authorId"] }]
    }
  },
  "admin": {
    "$extend": ["user"],
    "post": {
      "update": [{ "possession": "any", "attributes": ["*"] }]
    }
  }
}
```

### Flat List Form (DB‑friendly)

The same model as one row per rule, plus one `$extend` row per role — ideal for
a relational table:

```json
[
  { "role": "user",  "resource": "post", "action": "read",
    "possession": "any", "attributes": ["*", "!authorId"] },
  { "role": "admin", "resource": "post", "action": "update",
    "possession": "any", "attributes": ["*"] },
  { "role": "admin", "$extend": ["user"] }
]
```

Both shapes are accepted by the constructor and `setGrants()`:

```js
const ac = new AccessControl(rows);     // flat list
const ac2 = new AccessControl(object);  // object form — equivalent
```

## A Complex Example (Conditions, Deny, Groups)

This model uses every serializable grant feature: a condition, a `deny` rule
(deny‑overrides), multiple rules per action, inheritance, and a group/category
grant via a `/`‑qualified name.

### Object Form

```json
{
  "author": {
    "$extend": ["user"],
    "post": {
      "create": [{ "possession": "own", "attributes": ["*", "!status"] }],
      "publish": [
        {
          "possession": "own",
          "attributes": ["*"],
          "condition": ["$.post.status", "==", "draft"]
        }
      ]
    }
  },
  "moderator": {
    "$extend": ["author"],
    "post": {
      "publish": [{ "possession": "own", "attributes": ["*"], "effect": "deny" }]
    }
  },
  "staff": {
    "content/article": {
      "read": [{ "possession": "any", "attributes": ["title", "body"] }]
    }
  }
}
```

### Flat List Form (Same Model)

```json
[
  { "role": "author", "resource": "post", "action": "create",
    "possession": "own", "attributes": ["*", "!status"] },
  { "role": "author", "resource": "post", "action": "publish",
    "possession": "own", "attributes": ["*"],
    "condition": ["$.post.status", "==", "draft"] },
  { "role": "moderator", "resource": "post", "action": "publish",
    "possession": "own", "attributes": ["*"], "effect": "deny" },
  { "role": "staff", "resource": "content/article", "action": "read",
    "possession": "any", "attributes": ["title", "body"] },
  { "role": "author", "$extend": ["user"] },
  { "role": "moderator", "$extend": ["author"] }
]
```

:::note[Groups & categories are just names here]
A group/category grant is a rule whose `role`/`resource` is a `/`‑qualified name
(`staff`, `content/article`). The **membership** (`setup({ roles: { staff: […] },
resources: { content: […] } })`) is not a grant — re‑apply it on restore (it powers
`strict` and `getGroups()`/`getCategories()`).
:::

## `snapshot()` / `restore()`: The Whole Model in One Call

A complete model is **grants + gates + vocabulary**. `snapshot()` returns all
three as one plain‑JSON object (`{ grants, requirements, vocabulary }`);
`restore()` puts such an object back. Together they remove the boilerplate of
persisting and restoring each structure by hand.

```js
// persist — one JSON blob with everything
const snap = ac.snapshot();
await db.savePolicy(JSON.stringify(snap));

// rebuild on boot — one call
const ac = new AccessControl().restore(await db.loadPolicy());
```

`restore()` is a **full replace**: it `reset()`s the instance, then re‑applies
each section through its normal validated path. So the instance ends up **exactly
equal** to the snapshot — call it on a fresh *or* a populated instance, the result
is the same:

| Section | Re‑applied via |
| --- | --- |
| `grants` | `setGrants()` |
| `vocabulary` | `setup()` |
| `requirements` | `require()` / `category().require()` / `resource().require()` |

Because it routes through those methods, a restored snapshot is **validated** just
like hand‑written setup — reserved/gadget names are rejected, charset rules apply,
conditions are recompiled. It is **not** a raw `Object.assign` of internal state.

:::note[Need to add gates without wiping?]
`restore()` always replaces. To layer extra gates onto an existing model instead,
call `require()` / `category().require()` / `resource().require()` directly — see
[below](#require-gates-persist-separately).
:::

## Save & Restore (by Hand)

If you'd rather persist the grants on their own (e.g. only the grants change and
the gates/vocabulary are defined in code), the individual getters still work:

```js
// persist
await db.savePolicy(ac.getGrantsList()); // grants (rows)

// rebuild on boot
const ac = new AccessControl(await db.loadPolicy());
```

A grant rule row, fully expanded:

```js
{
  role: 'author',
  resource: 'post',
  action: 'publish',
  possession: 'own',                           // omitted ⇒ 'any'
  attributes: ['*'],
  condition: ['$.post.status', '==', 'draft'], // optional (canonical JSON)
  effect: 'deny'                               // optional (deny rule)
}
```

## `require()` Gates Persist Separately

`require()` gates are **not** part of the grants — they live in their own
structure, in three scopes (global, category, resource):

```js
ac.require('$.env == "prod"'); // global  — every check
ac.category('billing').require('$.ip cidr 10.0.0.0/8'); // category — billing/*
ac.resource('billing/invoice').require('$.mfa == true'); // resource — one resource
```

None of these appear in `getGrants()` / `getGrantsList()`. They show up in
`getRequirements()`, keyed by scope, with each condition in canonical form:

```json
{
  "global": [["$.env", "==", "prod"]],
  "categories": {
    "billing": [["$.ip", "cidr", "10.0.0.0/8"]]
  },
  "resources": {
    "billing/invoice": [["$.mfa", "==", true]]
  }
}
```

Persist those as their own rows — `target` is `null` for a global gate:

```json
[
  { "scope": "global",   "target": null,              "condition": ["$.env", "==", "prod"] },
  { "scope": "category", "target": "billing",         "condition": ["$.ip", "cidr", "10.0.0.0/8"] },
  { "scope": "resource", "target": "billing/invoice", "condition": ["$.mfa", "==", true] }
]
```

…and **re‑apply** them on restore. There is no raw `setRequirements()` setter —
gates are always re‑applied through the validated `require()` API. (Restoring the
whole model at once? [`restore()`](#snapshot--restore-the-whole-model-in-one-call)
does this for you.) Stored as flat scope rows, one loop handles all three scopes:

```js
for (const r of await db.loadRequirementRows()) {
  if (r.scope === 'global') ac.require(r.condition);
  else if (r.scope === 'category') ac.category(r.target).require(r.condition);
  else ac.resource(r.target).require(r.condition); // 'resource'
}
```

:::caution[Don't forget the gates]
A model restored from `getGrantsList()` alone has **no** `require()` gates. If a
gate was the only thing restricting a resource, omitting it on restore *widens*
access. Persist and restore grants **and** requirements (and `setup()` vocabulary)
— or just use `snapshot()` / `restore()`, which carry all three.
:::

## The Simplest Store: A Single JSONB Blob

If you don't need to query individual rules in SQL, skip the relational layout
entirely: store one `snapshot()` and rehydrate with `restore()`. One row, no
joins, exact round‑trip.

```sql
CREATE TABLE ac_policy (
  id         INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),  -- single-row table
  snapshot   JSONB NOT NULL,                            -- ac.snapshot()
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

```js
// persist — one upsert, everything that defines the model
await db.savePolicy(ac.snapshot());  // { grants, requirements, vocabulary }

// rebuild on boot — one call
const ac = new AccessControl({}, { policy: { strict: true } })
  .restore(await db.loadPolicy());
```

Prefer separate columns if you want to read or diff the parts independently —
`snapshot()` is just `{ grants, requirements, vocabulary }`, so split it across
three `JSONB` columns and pass them back as one object to `restore()`.

:::tip[Blob vs rows]
Reach for the **blob** when the policy is edited as a whole (deploys, an admin
"save" button) — it's the least code. Reach for the **relational** layout below
when you need SQL to query or audit individual rules (e.g. "every role that can
`delete` on `billing/*`"), or when rows are edited independently.
:::

## A SQL Schema (PostgreSQL)

One table for rule rows, one for inheritance, one for gates, plus the
vocabulary.

```sql
-- grant rules — one row per IGrant (multiple rules per action allowed)
CREATE TABLE ac_grants (
  id         BIGSERIAL PRIMARY KEY,
  role       TEXT NOT NULL,                          -- 'author' or group 'staff'
  resource   TEXT NOT NULL,                          -- 'post' or 'content/article'
  action     TEXT NOT NULL,                          -- 'create','publish',...
  possession TEXT CHECK (possession IN ('own','any')), -- NULL ⇒ 'any'
  effect     TEXT NOT NULL DEFAULT 'grant'
             CHECK (effect IN ('grant','deny')),     -- deny-overrides
  attributes JSONB NOT NULL DEFAULT '["*"]'::jsonb,  -- glob notation
  condition  JSONB                                   -- NULL ⇒ unconditional
);
CREATE INDEX ix_ac_grants ON ac_grants (role, resource, action);

-- role inheritance ($extend rows)
CREATE TABLE ac_role_inheritance (
  role    TEXT NOT NULL,
  extends TEXT NOT NULL,
  PRIMARY KEY (role, extends)
);

-- require() gates — separate from grants; can only restrict
CREATE TABLE ac_requirements (
  id        BIGSERIAL PRIMARY KEY,
  scope     TEXT NOT NULL CHECK (scope IN ('global','category','resource')),
  target    TEXT,                                    -- NULL when scope = global
  condition JSONB NOT NULL
);

-- setup() vocabulary — for strict typo-checks & introspection
CREATE TABLE ac_roles      (name TEXT PRIMARY KEY, "group" TEXT);
CREATE TABLE ac_resources  (name TEXT PRIMARY KEY, category TEXT);
CREATE TABLE ac_actions    (name TEXT PRIMARY KEY);  -- custom (non-CRUD) actions
```

The billing gate above is just a row in `ac_requirements`:

```sql
INSERT INTO ac_requirements (scope, target, condition) VALUES
  ('category', 'billing', '["$.ip","cidr","10.0.0.0/8"]'::jsonb);
```

### MySQL Flavor

The same schema in MySQL (8.0+): `JSON` instead of `JSONB`, `AUTO_INCREMENT`
instead of `BIGSERIAL`, and back‑ticks around the reserved word `group`. MySQL
has no partial/`CHECK`‑on‑enum nicety, so `ENUM` carries the allowed values.

```sql
-- grant rules — one row per IGrant
CREATE TABLE ac_grants (
  id         BIGINT AUTO_INCREMENT PRIMARY KEY,
  role       VARCHAR(191) NOT NULL,
  resource   VARCHAR(191) NOT NULL,
  action     VARCHAR(191) NOT NULL,
  possession ENUM('own','any'),                        -- NULL ⇒ 'any'
  effect     ENUM('grant','deny') NOT NULL DEFAULT 'grant',
  attributes JSON NOT NULL,                            -- glob notation
  condition  JSON,                                     -- NULL ⇒ unconditional
  INDEX ix_ac_grants (role, resource, action)
);

-- role inheritance ($extend rows)
CREATE TABLE ac_role_inheritance (
  role    VARCHAR(191) NOT NULL,
  extends VARCHAR(191) NOT NULL,
  PRIMARY KEY (role, extends)
);

-- require() gates — separate from grants; can only restrict
CREATE TABLE ac_requirements (
  id        BIGINT AUTO_INCREMENT PRIMARY KEY,
  scope     ENUM('global','category','resource') NOT NULL,
  target    VARCHAR(191),                              -- NULL when scope = global
  condition JSON NOT NULL
);

-- setup() vocabulary — for strict typo-checks & introspection
CREATE TABLE ac_roles     (name VARCHAR(191) PRIMARY KEY, `group` VARCHAR(191));
CREATE TABLE ac_resources (name VARCHAR(191) PRIMARY KEY, category VARCHAR(191));
CREATE TABLE ac_actions   (name VARCHAR(191) PRIMARY KEY);
```

:::note[Why `VARCHAR(191)`]
Under the legacy `utf8mb4` + InnoDB index‑prefix limit, 191 is the longest a
single‑column index key can be. On current MySQL/MariaDB defaults you can raise
it; 191 is the safe portable choice for the indexed name columns.
:::

A runnable grants model, this schema and an Express integration live in the
repository's
[`examples/`](https://github.com/onury/accesscontrol/tree/master/examples) folder.

## Inspecting the Model

```js
ac.getGrants();        // object form (a frozen deep copy)
ac.getGrantsList();    // flat list form
ac.getRequirements();  // require() gates by scope (a deep copy)
ac.getVocabulary();    // setup() input: { roles, resources, actions }
ac.snapshot();         // all three at once: { grants, requirements, vocabulary }
```

`getVocabulary()` is the inverse of `setup()` — members come back **unqualified**
(`{ admins: ['admin'] }`, not `['admins/admin']`), so the result feeds straight
back in.

:::tip[Getters return detached copies]
All of these return deep copies — mutating a result can never alter the live
model (a `require()` gate can't be neutered through an introspection result).
`getGrants()` is additionally frozen; `snapshot()` returns a plain, editable bag.
:::

## Conditions & Custom Functions

Declarative `.where()` / `.require()` conditions serialize as canonical JSON
inside the rows/gates, so they persist for free. Custom `{ fn, args }` conditions
store only the **name + args** — re‑register the functions with
[`defineCondition()`](/accesscontrol/concepts/async/) on the instance that loads
the model.

:::caution[Validate names from untrusted stores]
A grants object loaded from a store still goes through full validation:
reserved/gadget names (`__proto__`, …) are rejected, and (under the default
ASCII [charset](/accesscontrol/concepts/strict/#charset)) non‑ASCII names throw.
If the store is editable by lower‑privileged users, also read
[Security › Conditions from untrusted sources](/accesscontrol/security/#conditions-from-untrusted-sources).
:::
