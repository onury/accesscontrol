---
title: Require Gates
description: Mandatory restrictions with .require() at global, category and resource scope — they can only narrow access, never widen it.
---

`.require()` adds a **mandatory gate**: a condition that must pass for a check to
be granted, independent of any role's grants.

```
granted = (a grant matches) AND (every applicable gate passes)
```

:::note[Gates can only restrict]
Unlike [`.where()`](/accesscontrol/concepts/conditions/) (which conditionally
*grants*), a gate can never widen access — adding one can only take access away.
That makes gates the right tool for cross‑cutting rules.
:::

## Scopes

A gate applies at one of three scopes. On a check, the applicable gates are the
**global** ones, plus the resource's **category** gates, plus the **resource**
gates — all must pass.

```js
ac.require('$.env == prod');                       // global: every check
ac.category('billing')
  .require('$.ip cidr 10.0.0.0/8');                 // any billing/* resource
ac.resource('billing/invoice')
  .require('$.mfa == true');                        // just billing/invoice
```

## Example: Layered Gates

```js
const ac = new AccessControl(grants, {
  context: { env: process.env.NODE_ENV }
});

ac.require('$.env == prod');                        // 1) prod only
ac.category('billing').require('$.ip cidr 10.0.0.0/8'); // 2) + from the VPN
ac.resource('billing/invoice').require('$.mfa == true'); // 3) + MFA

// passes only if prod AND in-VPN AND mfa — on top of a matching grant
ac.can('accountant', { ip, mfa: true })
  .readAny('billing/invoice').granted;
```

A denial by a gate surfaces as `reason: 'require_failed'` on the
[`access` event](/accesscontrol/concepts/events/).

## Inspecting Gates

```js
ac.getRequirements();
// { global: [...], categories: { billing: [...] }, resources: { 'billing/invoice': [...] } }
```

:::tip[The result is a detached copy]
`getRequirements()` returns a deep clone — mutating it cannot alter the live
gates. (A `require()` gate must not be neuterable through an introspection
result.)
:::

## Async Gates

A gate may use a custom `{ fn, args }` condition; like conditional grants, that
moves the check to the [async path](/accesscontrol/concepts/async/)
(`grantedAsync` / `checkAsync`).
