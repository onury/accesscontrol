---
title: Resources, Attributes & Filtering
description: Define resources, scope access to attributes with glob notation, and filter data down to the allowed fields.
---

A **resource** is a uniquely named thing being accessed — a document, a DB
record, a file, a relationship. Whether something is a distinct resource is a
**design decision**.

```js
ac.grant('user')
  .createAny('account')
  .updateOwn('account', ['*', '!password', '!email'])
  .updateOwn('credentials');
```

A resource is defined the first time you grant/deny on it (or declared up front
with [`setup()`](/accesscontrol/concepts/groups/)).

```js
ac.hasResource('banana');               // false
ac.grant('monkey').createOwn('banana'); // defined now
ac.hasResource('banana');               // true
ac.getResources();                      // ['account', 'credentials', 'banana']
```

## Attributes (Glob Notation)

Each grant scopes access to a set of attributes using
[glob notation](https://github.com/onury/notation): `*` (all), `!` (negate),
and nested dotted paths.

```js
ac.grant('user').readOwn('account', [
  '*',          // all attributes…
  '!password',  // …except password
  'profile.*'   // (nested paths are supported)
]);
```

:::note[Negation-only implies `*`]
A list with only negations gets an implied leading `*` — `['!password']` means
"everything except password" (`['*', '!password']`), not "nothing".
:::

Omitting attributes defaults to `['*']` for a grant. An explicit empty array
`[]` is preserved — a grant with `[]` (or a `deny` with omitted attributes)
allows **no** attributes, so `granted` is `false`.

## Filtering Data

`filter()` returns a **deep copy** of a record (or array of records) containing
only the allowed attributes — handy for shaping API responses.

```js
ac.grant('user').readOwn('account', ['*', '!password', 'profile.*']);

const perm = ac.can('user').readOwn('account');
perm.attributes;            // ['*', '!password', 'profile.*']
perm.filter(accountRecord); // a copy without `password`
```

Filtering an array maps over each element:

```js
const visible = ac.can('user').readAny('account').filter(accounts);
```

:::tip[`granted` vs `attributes`]
`granted` tells you *whether* access is allowed; `attributes` tells you *what
fields*. A grant of `['!password']` is still `granted: true` (it allows all but
one field); a grant of `[]` is `granted: false`.
:::

## Categories

Related resources can share a **category** with `/` (e.g. `media/photo`,
`media/video`), enabling category‑wide grants and gates without name collisions
(`media/photo` and `legal/photo` are distinct). See
[Groups & Categories](/accesscontrol/concepts/groups/).
