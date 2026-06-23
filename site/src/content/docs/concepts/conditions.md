---
title: Conditions (ABAC)
description: Attach declarative conditions to grants with .where(), supply check-time data via context, and use the full operator set.
---

A **condition** decides *whether a grant applies* at check time, against a
**context** — this is the ABAC half of the engine. Attach one with `.where()`
and supply data per check.

```js
ac.grant('manager')
  .where('$.order.value <= 100000')
  .updateAny('order', ['*']);

ac.can('manager')
  .with({ order: { value: 5000 } })
  .updateAny('order').granted; // true

ac.can('manager')
  .with({ order: { value: 250000 } })
  .updateAny('order').granted; // false (condition fails)
```

## Supplying Context

Three equivalent ways to pass per‑check data:

```js
ac.can('manager', { order }).updateAny('order');          // 2nd arg
ac.can('manager').with({ order }).updateAny('order');      // fluent
ac.check({ role: 'manager', resource: 'order',
           action: 'update:any', context: { order } });    // one-shot
```

Ambient defaults can be set on the instance and are merged with (overridden by)
the per‑check context:

```js
const ac = new AccessControl(grants, { context: { env: process.env.NODE_ENV } });
```

## Operators

Operands are **notation paths** (`$.order.value`) read from the context, or
literals. Quote to force a string (`"100"` vs `100`).

| Group | Operators |
| --- | --- |
| Comparison | `==` `!=` `>` `>=` `<` `<=` |
| Membership | `in`, `contains` |
| String | `startsWith`, `endsWith`, `matches` |
| Time | `before`, `after`, `between` |
| Network | `cidr` |
| Combinators | `{ and }`, `{ or }`, `{ not }` |

```js
ac.grant('user')
  .where('$.user.id == $.doc.ownerId')
  .updateOwn('doc');

ac.grant('ops')
  .where({ and: ['$.env == prod', '$.ip cidr 10.0.0.0/8'] })
  .readAny('server');

ac.grant('night')
  .where('$.now.time between [22:00, 06:00]')  // overnight window
  .createAny('report');
```

The reserved `$.now.*` fields (`year`, `month`, `day`, `weekday`, `hour`,
`minute`, `time`, `date`) are auto‑injected; override `context.now` (a `Date` or
string) for deterministic tests and `context.tz` for the timezone.

## A Multi-clause Business Rule

Real policies often combine several conditions. Take: *a senior buyer may
**approve** a purchase order only if they are **not** its creator, it's in their
branch, its value exceeds 100,000, and it's within today's approval limit.* Every
clause maps to a path comparison; `{ and }` joins them:

```js
ac.grant('buyer/senior')
  .where({
    and: [
      '$.user.id != $.order.creatorId',           // not the creator
      '$.user.branch == $.order.branch',           // same branch
      '$.order.value > 100000',                     // over the threshold
      '$.order.approvedToday < $.user.dailyLimit'   // under today's limit
    ]
  })
  .action('approve', 'order', ['*']);

ac.can('buyer/senior', {
  user:  { id: 7, branch: 'NW', dailyLimit: 5 },
  order: { creatorId: 9, branch: 'NW', value: 250000, approvedToday: 2 }
}).do('approve', 'order').granted; // true
```

:::tip[There is no "other" possession — express it with a condition]
"Not the creator/owner" is exactly the *other*-than-own case. Rather than a
third possession, use an `any` grant (the default) plus a condition:

```js
// "any record the user does NOT own"
.where('$.user.id != $.order.creatorId')
```
This composes with the rest of the rule, so a separate `other` possession would
be redundant. (`own` + ownership handles the owned case; see
[Ownership](/accesscontrol/concepts/ownership/).)
:::

A clause that needs a live number (e.g. `approvedToday`) is supplied in the
check `context`. If it requires I/O (a DB count), compute it before the check or
use a [custom condition function](/accesscontrol/concepts/async/).

## How Conditions Are Parsed, Cast & Stored

A condition can be written four ways, and all of them are accepted anywhere a
condition is taken (`.where()`, [`.require()`](/accesscontrol/concepts/gates/),
and the `condition` field of a stored rule):

```js
'$.order.value <= 100000'                 // 1. string sugar (what you write)
['$.order.value', '<=', 100000]           // 2. canonical leaf  [path, operator, value]
{ and: [ /* …conditions… */ ] }           // 3. combinator: and | or | not
{ fn: 'ipAllowed', args: { cidr: '…' } }  // 4. custom function (see Async)
```

Internally there is **one** representation — the canonical JSON above. Strings
are *compiled* into it; combinators are compiled recursively; `{ fn }` is passed
through untouched.

### Parsing the String Form

A leaf string is tokenized into exactly three parts — **`path` `operator`
`value`** — by recognizing the operator keyword/symbol ([see the table
above](#operators)). The left side must be a `$.`-path; the right side (the
**value**) is then *cast* by its token:

| Token looks like | Becomes | Example |
| --- | --- | --- |
| `true` / `false` | boolean | `$.active == true` → `true` |
| `null` | null | `$.deletedAt == null` → `null` |
| a number | number | `$.value <= 100000` → `100000` |
| `$.something` | **path reference** (compared field-to-field) | `$.user.id == $.doc.ownerId` |
| `[a, b]` | array (each item cast the same way) | `$.role in [admin, staff]` |
| `HH:MM` / `YYYY-MM-DD` (with time/date ops) | time / date | `$.now.time between [22:00, 06:00]` |
| `1.2.3.0/24` (with `cidr`) | CIDR range | `$.ip cidr 10.0.0.0/8` |
| anything else | **string** | `$.status == draft` → `'draft'` |

Values with spaces or characters that would confuse the tokenizer must be
**quoted** — `'$.title == "in review"'` → `['$.title', '==', 'in review']`.
Nesting depth is bounded (deeply nested `and`/`or`/`not` throws), and the whole
thing is validated on the way in regardless of which form you used.

### Why the Array Form Avoids Surprises

Because the string is *inferred*, the array form is the precise one — you supply
the exact value and type yourself, with no parsing and no escaping:

```js
'$.code == 007'              // → number 7   (leading zeros lost!)
['$.code', '==', '007']      // → string '007'

'$.name == "O'Brien"'        // needs careful quoting
['$.name', '==', "O'Brien"]  // just a value
```

This is also why a value that *looks* like a path is treated as one in a string
(`$.a == $.b`), whereas in the array you decide: `['$.a','==','$.b']` (compare
fields) vs `['$.a','==','"$.b"']`-style quoting is unnecessary — pass the literal
you mean.

### What Gets Stored

The compiled canonical form is what every reader returns —
`getGrants()`, `getGrantsList()`, `getRequirements()`, and `snapshot()` — as
**frozen deep copies**. So your database / JSON column holds arrays and
combinator objects, never the sugar string:

```js
ac.grant('manager').where('$.order.value <= 100000').updateAny('order');
ac.getGrants().manager.order.update[0].condition;
// → ['$.order.value', '<=', 100000]
```

That stored shape is deliberately the one to persist, because it:

- **needs no re-parsing** on load — deterministic, and stored data can't throw a
  parse error later;
- **preserves exact types** (`'007'` stays a string, `5` stays a number);
- **needs no escaping**, and is trivial to **generate or query from code/SQL**.

**Rule of thumb:** hand-write the string sugar; **store and generate the array.**
They are interchangeable as input — the array is simply the normalized output the
engine keeps.

## Regular Expressions

:::caution[`matches` is opt-in]
The `matches` operator is **disabled by default** (regular expressions are a
ReDoS surface). Enable it only for trusted condition sources:

```js
new AccessControl(grants, { engine: { allowRegex: true } });
ac.grant('user').where('$.file matches \\.pdf$').readAny('doc');
```

When enabled, patterns are screened for catastrophic backtracking. For fully
untrusted authors, prefer a [custom function](/accesscontrol/concepts/async/)
instead. See [Security](/accesscontrol/security/#regular-expressions-redos--opt-in).
:::

## `where` vs `require`

`.where()` conditionally **grants**; [`.require()`](/accesscontrol/concepts/gates/)
is an independent gate that can only **restrict**. They compose:
`granted = (a grant matches) AND (every applicable gate passes)`.

## Custom / Async Conditions

Business logic that needs I/O lives in a registered function referenced as
`{ fn, args }` — see [Async & Custom Functions](/accesscontrol/concepts/async/).
