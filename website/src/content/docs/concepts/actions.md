---
title: Actions & Possession
description: CRUD and custom actions via .action()/.do(), and the any vs own possession model.
---

An **action** is the kind of operation performed on a resource. The CRUD verbs
are built in, and v3 lets you use **any** custom action name.

## CRUD helpers

The named helpers are sugar for the four CRUD actions × two possessions:

```js
ac.grant('user')
    .createOwn('video')   // create + own
    .readAny('video')     // read + any
    .updateOwn('video')   // update + own
    .deleteAny('video');  // delete + any
```

A typical mapping (you decide what each *means* — a `create` might send an SMS,
a `delete` might be a soft‑delete `UPDATE`):

| AccessControl | REST/HTTP       | Database |
| ------------- | --------------- | -------- |
| `create`      | `POST`          | `INSERT` |
| `read`        | `GET`           | `SELECT` |
| `update`      | `PUT` / `PATCH` | `UPDATE` |
| `delete`      | `DELETE`        | `DELETE` |

## Custom actions

CRUD helpers are sugar over the generic `.action()` (and its alias `.do()`),
which accept any action name. Possession travels with the `:own` / `:any`
convention (omit ⇒ `any`).

```js
// granting
ac.grant('editor')
  .action('publish', 'article', ['*']);        // publish (any)
ac.grant('author')
  .action('publish:own', 'article', ['*']);    // ownership-gated publish

// checking
ac.can('editor').do('publish', 'article').granted;
ac.can('author', { user, article })
  .do('publish:own', 'article').granted;
ac.can('admin').do('update', 'post').granted;  // CRUD via .do() too
```

:::note[Custom actions are first-class]
A custom action behaves exactly like a CRUD action: it supports possession,
conditions, deny‑overrides, inheritance and filtering. The CRUD names are just
convenience.
:::

## Introspecting actions

`getActions()` lists the action names in the model. Pass a role (or roles) to
scope it to what that role can do — **including inherited** actions:

```js
ac.grant('user').readOwn('profile');
ac.grant('admin').extend('user').deleteAny('post').createAny('post');

ac.getActions();        // ['read', 'delete', 'create']  (all)
ac.getActions('user');  // ['read']
ac.getActions('admin'); // ['create', 'delete', 'read']  (own + inherited)
```

It throws if a given role doesn't exist. (Companions: `getRoles()`,
`getResources()`.)

## Possession: `any` vs `own`

- **`any`** — any record of the resource.
- **`own`** — only records the requester owns.

Grants **cascade** from `any` to `own`: a blanket `any` grant also satisfies an
`own` check (if you can act on *any* record, you can act on your *own*).

```js
ac.grant('admin').updateAny('order', ['*']);
ac.can('admin').updateOwn('order').granted;   // true (any ⊇ own)
```

`own` only *means* "owned" if you tell the engine how ownership is determined —
see [Ownership](/accesscontrol/concepts/ownership/). With no resolver
configured, `own` keeps its v2 behavior (it selects the attribute set; you
enforce ownership).

:::caution[`matches` and strict actions]
A custom action name is just a name. To catch typos in action names at check
time, enable [`strict.actions`](/accesscontrol/concepts/strict/). Unrelated:
the `matches` condition operator is opt‑in — see
[Conditions](/accesscontrol/concepts/conditions/#regular-expressions).
:::
