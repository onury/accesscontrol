---
title: Express Integration
description: A reusable authorization middleware that checks access, loads the record for ownership, and filters the response.
---

A small middleware factory covers most REST handlers: it loads the record (for
`own` checks and conditions), checks access **fail‑closed**, and exposes the
resolved permission so the handler can filter its response.

```js
import { AccessControl } from 'accesscontrol';

const ac = new AccessControl(grants, {
  policy: { ownerField: 'ownerId' },
  context: { env: process.env.NODE_ENV }
});

function authorize(action, resource, loadRecord) {
  return async (req, res, next) => {
    try {
      const record = loadRecord ? await loadRecord(req) : undefined;
      const ctx = { ip: req.ip, user: req.user, [resource]: record };

      // tryCan: a thrown error becomes a denial, never an accidental allow
      const perm = ac.tryCan(req.user.role, ctx).action(action, resource);
      if (!perm.granted) return res.status(403).end();

      req.permission = perm;
      next();
    } catch {
      res.status(403).end();
    }
  };
}
```

Use it per route; filter the response down to the granted attributes:

```js
router.get(
  '/articles/:id',
  authorize('read:any', 'article'),
  async (req, res) => {
    const article = await db.findArticle(req.params.id);
    res.json(req.permission.filter(article));
  }
);

router.patch(
  '/orders/:id',
  authorize('update:own', 'order', (req) => db.getOrder(req.params.id)),
  async (req, res) => {
    const data = req.permission.filter(req.body); // strip disallowed fields
    res.json(await db.updateOrder(req.params.id, data));
  }
);
```

:::tip[Async conditions]
If any grant/gate uses a custom `{ fn }` condition, resolve with the async
accessor instead:

```js
const perm = ac.tryCan(req.user.role, ctx).action(action, resource);
if (!(await perm.grantedAsync)) return res.status(403).end();
```
:::

:::note[Audit for free]
Add one listener and every request's decision is logged — including denials and
their `reason`:

```js
ac.on('access', (e) => logger.info('authz', e));
```
:::

A fuller, runnable version (ownership, custom actions, audit) lives in the
repository's
[`examples/express-middleware.example.ts`](https://github.com/onury/accesscontrol/blob/master/examples/express-middleware.example.ts).
