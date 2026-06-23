---
title: Strict Mode, Errors & Names
description: Typo-protection with strict mode, the stable err.code contract, safe (redacted) error messages, and the configurable name charset.
---

Access management is sensitive, so AccessControl **never fails silently**. This
page covers how it surfaces problems and the knobs that control naming and error
output.

## Strict mode (typo protection)

`policy.strict` turns unknown names into loud errors instead of silent denials.
It's a boolean or a per‑key object.

```js
new AccessControl(grants, {
  policy: { strict: { actions: true, resources: true } }
});
```

| key | default | effect |
| --- | --- | --- |
| `roles` | **on** | unknown role at check time → throws `ROLE_NOT_FOUND` |
| `checks` | **on** | an unverifiable `own` check (record/owner missing) → deny |
| `actions` | off | unknown action → throws `UNKNOWN_ACTION` (else silent deny) |
| `resources` | off | unknown resource → throws `UNKNOWN_RESOURCE` (else deny) |

`strict: true` turns all four on; `strict: false`, all off. The known sets come
from the grants, plus CRUD (actions), plus anything you declared via
[`setup()`](/accesscontrol/concepts/groups/) or the `policy.actions` /
`policy.resources` allow‑lists.

:::tip[Develop strict, fail loud]
Enable `actions`/`resources` in development and use
[`can()`](/accesscontrol/best-practices/#can-vs-trycan) so a typo throws in
tests. On the request path use `tryCan()` so the same situation denies instead.
:::

:::caution[`strict: true` is not automatically "more secure"]
Strict mode is **typo/misconfiguration protection**, not an access control. It
doesn't change *who* can do *what* — denials are identical with it on or off. It
only turns an *unknown* name from a silent `granted:false` into a **throw**. That
can even work *against* you: a thrown error a caller mishandles (a `catch` that
falls through to "allow") fails **open**. So treat strict as a development aid,
keep it paired with [`tryCan()`](/accesscontrol/best-practices/#can-vs-trycan) on
the request path, and never rely on it as a security boundary.
:::

## Errors never fail open

A **denial** returns `granted: false`. A genuine fault throws an
`AccessControlError`. Detect it and branch on its **code** — not its message.

```js
import { AccessControl } from 'accesscontrol';

try {
  ac.can(role).readAny('post');
} catch (err) {
  if (AccessControl.isACError(err)) {
    log(err.code, err.role, err.resource, err.action);
  }
}
```

:::danger[A thrown error means deny, never allow]
On the request path, don't let a `catch` fall through to "allow". Either branch
explicitly on a denial, or use
[`tryCan()`](/accesscontrol/best-practices/#can-vs-trycan), which never throws.
See [Security › Fail-closed checks](/accesscontrol/security/#fail-closed-checks).
:::

### Error codes

Every `AccessControlError` carries a stable `err.code` (the `ErrorCode` enum) —
the part of the API you should branch on. Messages are redacted by default and
may change wording.

| code | when |
| --- | --- |
| `INVALID_NAME` | empty/malformed name |
| `RESERVED_NAME` | a reserved keyword (`__proto__`, `prototype`, `constructor`, `_`) |
| `INVALID_QUERY` | malformed check query (`IQueryInfo`) |
| `INVALID_SETUP` | malformed `setup()` vocabulary |
| `INVALID_GRANT` | invalid grant rule / grants object |
| `INVALID_ACTION` | invalid action name or possession |
| `ROLE_NOT_FOUND` | referenced role doesn't exist |
| `INVALID_INHERITANCE` | self / cross / non‑existent inheritance |
| `UNKNOWN_ACTION` / `UNKNOWN_RESOURCE` | strict‑mode unknown name |
| `LOCKED` | mutation attempted after `lock()` |
| `ASYNC_REQUIRED` | a `{ fn }` condition was hit on the sync path |
| `INVALID_CONDITION` | malformed / too‑deeply‑nested condition |
| `UNKNOWN_CONDITION_FN` | unregistered custom function name |
| `REGEX_DISABLED` / `UNSAFE_REGEX` | `matches` disabled, or an unsafe pattern |

```js
import { ErrorCode } from 'accesscontrol';

if (err.code === ErrorCode.ROLE_NOT_FOUND) { /* … */ }
```

### Namespacing codes (`engine.errorCodePrefix`)

Codes like `INVALID_NAME` or `INVALID_QUERY` are generic and may collide with
your own system's codes. Prefix every AC code to namespace them:

```js
const ac = new AccessControl(grants, { engine: { errorCodePrefix: 'AC_' } });
// now err.code === 'AC_ROLE_NOT_FOUND'
```

:::caution[A prefix changes the comparison]
With a prefix set, the bare‑enum comparison no longer matches — compare against
the prefixed value:

```js
const PREFIX = 'AC_';
if (err.code === PREFIX + ErrorCode.ROLE_NOT_FOUND) { /* … */ }
```
The default prefix is `''`, so `err.code === ErrorCode.X` works out of the box.
:::

## Safe error messages

By default (`engine.safeErrors: true`), error **messages** omit caller‑supplied
values so request data doesn't leak into logs. The values remain on the
structured fields.

```js
const e = grab(() => ac.can('ghost').readAny('post').granted);
e.message; // "Role not found."   (redacted — safe to log)
e.role;    // "ghost"             (available programmatically)
```

Turn it off for verbose, developer‑friendly messages:

```js
new AccessControl(grants, { engine: { safeErrors: false } });
// → "Role not found. Got: \"ghost\"."
```

See [Security › Error messages](/accesscontrol/security/#error-messages--information-disclosure).

## Charset

Names (roles, resources, actions, groups, categories) are validated against a
character set. The default is ASCII; opt into Unicode for i18n.

```js
import { Charset } from 'accesscontrol';

new AccessControl(grants, { engine: { charset: Charset.UNICODE } });
ac.grant('café').readAny('café');  // allowed under UNICODE
```

| value | allowed | notes |
| --- | --- | --- |
| `Charset.ASCII` (default) | `[A-Za-z0-9_-]` | rules out homograph attacks |
| `Charset.UNICODE` | Unicode letters/digits + `_` `-` | ⚠️ homograph risk |

:::caution[Unicode names carry homograph risk]
`аdmin` (Cyrillic `а`) is a *different* role from `admin` (Latin `a`). Under
`UNICODE`, NFC‑normalize names before passing them in. Structural characters
(`/ : $ * !`) and the reserved gadget names stay rejected in **every** mode. See
[Security › Names & homographs](/accesscontrol/security/#names--homographs-charset).
:::
