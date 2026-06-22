---
title: Groups & Categories
description: Declare a vocabulary with setup(), then grant to a whole role group or resource category at once — the safe, bounded alternative to wildcards.
---

Role **groups** and resource **categories** let you grant to many roles/resources
at once, *bounded* to a declared vocabulary — the safe alternative to a blanket
`*`.

## Declare the vocabulary

```js
ac.setup({
  roles:     { admins: ['admin', 'moderator'], _: ['user'] },
  resources: { media: ['photo', 'video'], _: ['profile'] },
  actions:   ['publish']    // declare custom actions for strict mode
});
```

Members become qualified `group/member` names (`admins/admin`, `media/photo`).
The reserved `_` key lists **ungrouped / uncategorized** members. `setup()` is
additive — call it as many times as you like.

:::note[A plain array works too]
When you don't need grouping, pass an array — it's treated as the `_` bucket:

```js
ac.setup({ roles: ['user', 'admin'], resources: ['post', 'comment'] });
```
:::

## Bulk grant to a group / category

Grant once to a group and/or category; members inherit dynamically at check time.

```js
ac.grant('admins').readAny('media');                   // group × category

ac.can('admins/admin').readAny('media/photo').granted; // true
ac.can('admins/moderator').readAny('media/video').granted; // true
```

Names never collide across categories — `media/photo` and `legal/photo` are
distinct resources.

## Introspection

```js
ac.group('admins').getRoles();       // ['admins/admin', 'admins/moderator']
ac.category('media').getResources();  // ['media/photo', 'media/video']
ac.getGroups();                       // ['admins']  ('_' excluded)
ac.getCategories();                   // ['media']
ac.hasGroup('admins');                // true
ac.hasCategory('media');              // true
```

Membership is declared once with [`setup()`](#declare-the-vocabulary) (additive —
call it again to add more). It feeds `strict` typo‑checks and the introspection
above; it does **not** itself grant access — a `group/member` inherits the
group's grants *by name* (see above), independent of the roster. To change
access, use `grant(group)` / `deny` / `removeRoles`.

:::tip[Why not just use `*`?]
A wildcard role/resource is a data‑leak footgun — one careless grant exposes
everything, including resources added later. Groups/categories give you the same
"grant to many at once" ergonomics, but bounded to names you explicitly
declared. (Wildcard role/resource grants are intentionally not supported; `*`
stays attributes‑only.)
:::

## Removing

```js
ac.removeGroup('admins');     // members stop inheriting the group's grants
ac.removeCategory('media');   // member resources stop inheriting category grants
```
