---
title: Roles & Inheritance
description: Define roles, inherit grants with extend(), and understand deny-overrides — where an explicit deny always wins.
---

A **role** models *who* is acting (a job/title). You define a role the first time
you `grant()` or `deny()` on it — or declare it up front with
[`setup()`](/accesscontrol/concepts/groups/).

```js
import { AccessControl } from 'accesscontrol';

const ac = new AccessControl();

ac.grant('user')
    .createOwn('video')
    .readAny('video')
  .grant('admin')          // switch role, keep the chain
    .extend('user')        // inherit user's grants
    .deleteAny('video');
```

## Inheritance

A role inherits others with `.extend()`. Grants are **additive**: the child gets
its own grants plus everything its parents grant.

```js
ac.grant('user').readAny('post', ['*']);
ac.grant('moderator').extend('user');

ac.can('moderator').readAny('post').granted; // true (inherited)
```

You can extend multiple roles, and chains are flattened:

```js
ac.grant('support').readAny('ticket', ['*']);
ac.grant('agent').extend(['user', 'support']);
ac.grant('lead').extend('agent');   // lead → agent → user, support
```

:::caution[Cross-inheritance is rejected]
A role cannot extend itself, and two roles cannot extend each other. Such a
cycle throws `err.code === 'INVALID_INHERITANCE'`. This protects you from
infinite loops in the hierarchy.
:::

## Deny-overrides

An explicit `deny` always wins — even over an inherited grant. This lets a child
role carve a field (or action) back out:

```js
ac.grant('user').readAny('post', ['*']);
ac.grant('moderator').extend('user');
ac.deny('moderator').readAny('post', ['secret']); // carve a field back

ac.can('moderator').readAny('post').attributes;   // ['*', '!secret']
```

:::note[Deny does not cascade across possession]
A `deny('x').createAny('post')` does **not** remove `create:own` — denies are
possession‑specific. Grants, on the other hand, cascade: an `any` grant also
satisfies an `own` check.
:::

## Introspection

```js
ac.hasRole('admin');             // boolean (single or array)
ac.getRoles();                   // ['user', 'admin']
ac.getInheritedRolesOf('admin'); // ['user']
ac.removeRoles('admin');         // also strips it from other roles' $extend
```

## Multiple roles in one check

Pass an array to check "at least one of these roles allows it". Attributes are
the **union** across the roles:

```js
ac.can(['user', 'support']).readAny('ticket').granted;
```
