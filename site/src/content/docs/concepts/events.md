---
title: Events & Auditing
description: Subscribe to access, change and error events — a dependency-free, fault-isolated audit stream for every decision.
---

AccessControl has a small, dependency‑free event emitter. The headline event is
`access`, which fires on **every** resolved check (granted *and* denied) — your
ready‑made audit log.

```js
ac.on('access', (e) => audit(e));
ac.on('change', (e) => log(e.type));
ac.on('error', (e) => report(e.error));
```

## `access` — the Audit Stream

```js
ac.on('access', (e) => {
  // {
  //   roles, resource, category, action, possession,
  //   granted, attributes, reason, context, timestamp
  // }
  audit(e);
});
```

`reason` explains a denial — one of:

| reason | meaning |
| --- | --- |
| `no_grant` | no matching grant for the role/resource/action |
| `condition_failed` | a `.where()` condition didn't hold |
| `ownership_failed` | an `own` rule couldn't verify ownership |
| `require_failed` | a `.require()` gate didn't pass |

```js
ac.on('access', (e) => {
  if (!e.granted) metrics.increment(`denied.${e.reason}`);
});
```

## `change` — Policy Edits

Fires when the model is mutated (`grant`, `deny`, `extend`, `set_grants`,
`setup`, `require`, `remove`, `reset`, `lock`). The payload carries the `type`
and a `detail`:

```js
ac.on('change', (e) => log(`policy ${e.type}`, e.detail));
```

## `error` — Faults

Fires when a check or operation throws (carries the `AccessControlError`). It
fires even under [`tryCan()`](/accesscontrol/best-practices/#can-vs-trycan),
where the check itself returns `granted: false` — so you still observe the fault.

```js
ac.on('error', (e) => report(e.error)); // e.error is an AccessControlError
```

## Subscription Management

```js
const onAccess = (e) => audit(e);
ac.on('access', onAccess);
ac.once('change', (e) => init(e));  // auto-removes after the first event
ac.off('access', onAccess);          // remove one
ac.off('access');                    // remove all 'access' listeners
```

:::note[Listeners are observational and isolated]
A listener cannot alter a decision, and a **throwing listener never breaks a
check** — exceptions in listeners are swallowed. Keep audit side effects (DB
writes, network) off the hot path or dispatch them asynchronously.
:::

:::tip[Zero overhead when unused]
Events are only assembled when a listener is registered for that name — if you
never call `on('access', …)`, checks pay nothing for it.
:::
