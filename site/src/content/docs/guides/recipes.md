---
title: Recipes & Integrations
description: Practical patterns — restrict to own records, UI visibility, React, and sharing one policy across microservices.
---

Short, copy-paste answers to the questions that come up most. Each builds on the
same model you already have — no extra concepts.

## Restrict a User to Their Own Records (ABAC)

The classic "an author may edit **their own** articles, not everyone's". Configure
ownership once, grant `own`, and pass the record in the check context — the
library enforces it.

```js
const ac = new AccessControl({}, { policy: { ownerField: 'authorId' } });
ac.grant('author').updateOwn('article', ['title', 'body']);

// later, in your handler — load the record first, then check
const article = await db.articles.find(id);
const perm = ac.can('author', { user: { id: userId }, article }).updateOwn('article');

if (!perm.granted) return res.status(403).end();
await db.articles.update(id, perm.filter(req.body)); // only allowed fields
```

For anything more involved than a field match, use a custom resolver or a
`.where()` condition:

```js
new AccessControl({}, { policy: { owner: (ctx) => ctx.article.authorId === ctx.user.id } });
ac.grant('author').where('$.article.status != "locked"').updateOwn('article', ['*']);
```

## Show / Hide UI by Permission

AccessControl returns the decision; rendering is your app's job. Compute a plain
boolean (or the allowed attributes) and branch on it.

```js
// any framework / template
if (ac.tryCan(role).readAny('dashboard:revenue').granted) {
  render(revenueWidget);
}
```

:::tip[Use `tryCan()` on the view path]
`tryCan()` never throws (an invalid query or strict miss → `granted: false`), so
a rendering bug can't turn into an accidental *allow*.
:::

To drive a whole UI, send the client a small capability map instead of the raw
grants:

```js
const caps = {
  canEditPost: ac.tryCan(role).updateAny('post').granted,
  revenue: ac.tryCan(role).readAny('dashboard:revenue').granted
};
res.json(caps);
```

## React

There's nothing React-specific to install — call AccessControl (usually on the
server, or wherever your `ac` instance lives) and consume the booleans.

```jsx
// pass the capability map (above) down via context
const Caps = React.createContext({});
const useCan = (key) => React.useContext(Caps)[key];

function EditButton() {
  return useCan('canEditPost') ? <button>Edit</button> : null;
}
```

:::caution[The client is never the boundary]
UI gating is UX, not security — anything the browser can flip. Always re-check on
the server for every mutating request (e.g. with the
[Express middleware](/accesscontrol/guides/express/)).
:::

## Filter API Responses to Allowed Fields

`permission.filter()` strips a payload (object **or array**) down to the granted
attributes — so a single role definition shapes what each caller sees.

```js
const perm = ac.can(role).readAny('account');
res.json(perm.filter(accounts)); // array → each item filtered
```

## One Policy Across Microservices

Keep a **single source of truth** for the model and distribute it; don't redefine
grants per service. The whole model serializes to plain JSON via
[`snapshot()`](/accesscontrol/concepts/serialization/) (grants + gates +
vocabulary) or `getGrantsList()` (DB-friendly rows).

```js
// authority service — persist on change
await store.put('policy', JSON.stringify(ac.snapshot()));

// each consumer service — load on boot (and on a change signal)
const ac = new AccessControl().restore(await store.get('policy'));
```

How you move the blob is your call — all are fine because it's just JSON:

- **Shared store** (Redis/S3/DB row) the services poll or subscribe to — simplest.
- **Config/secret mount** redeployed with the fleet — no runtime dependency.
- **A small policy service** exposing the snapshot over REST/RPC; consumers cache it.

:::note[Keep enforcement local]
Distribute the *model*, but run the **check** inside each service (it's pure and
fast). A central "ask the auth service per request" hop adds latency and a
single point of failure — reserve it for cases where the model truly can't be
replicated.
:::
