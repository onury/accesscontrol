# Frequently Asked Questions

> Short answers with pointers into the guides. New to v3? See
> [What's New](/accesscontrol/whats-new/) and
> [Migrating from v2](/accesscontrol/migration/).

### What is "Access Control"?

The selective restriction of **access** to a **resource**. AccessControl models
*who* is acting (**roles**), *what* they're doing (**actions**), *what* they act
on (**resources** and their **attributes**), and decides **whether** it's
allowed — optionally constrained by **conditions**, **ownership**, and mandatory
**gates**. It merges [RBAC](https://en.wikipedia.org/wiki/Role-based_access_control)
and [ABAC](https://en.wikipedia.org/wiki/Attribute-Based_Access_Control).

### What's an "action"? A "resource"?

An **action** is the operation performed (the CRUD verbs, or any
[custom action](/accesscontrol/concepts/actions/)). A **resource** is a uniquely
named thing being accessed; what counts as a distinct resource is a design
decision. See [Resources](/accesscontrol/concepts/resources/).

### Do I still have to check ownership myself?

**No — that's the big v3 change.** Tell AccessControl how ownership is determined
once (`policy.ownerField` or `policy.owner`), pass the record in the check
context, and `own` is enforced. See [Ownership](/accesscontrol/concepts/ownership/).
With **no** resolver configured, `own` keeps its v2 behavior, so existing code
isn't silently locked down.

### `.where()` vs `.require()`?

`.where()` is a *conditional grant* — it can only **add** access under a
condition. `.require()` is a *mandatory gate* — independent of grants, it can
only **restrict**. See [Conditions](/accesscontrol/concepts/conditions/) and
[Require Gates](/accesscontrol/concepts/gates/).

### `policy` vs `context` — which goes where?

*If a condition reads it with `$.`, it's `context`; if the engine reads it to
decide behavior, it's `policy`.* See
[Best Practices › policy vs context](/accesscontrol/best-practices/#policy-vs-context).

### Sync or async checks?

Declarative checks are synchronous. A grant/gate that uses a custom function
(`{ fn, args }`) requires the async path (`grantedAsync` / `checkAsync`). See
[Async & Custom Functions](/accesscontrol/concepts/async/).

### Can I use AccessControl with a database?

Yes — it's storage‑agnostic. Persist the model as flat rows
(`getGrantsList()`) and rehydrate it; the round‑trip is exact. See
[Serialization & Databases](/accesscontrol/concepts/serialization/).

### How do I catch typos (unknown roles/actions/resources)?

Turn on [strict mode](/accesscontrol/concepts/strict/). `roles` is on by
default; enable `actions`/`resources` to throw on unknown names instead of
silently denying.

### How do I audit decisions?

Subscribe to the `access` event — it fires on **every** resolved check (granted
and denied) with a denial `reason`. See
[Events & Auditing](/accesscontrol/concepts/events/).

### What do I do when AccessControl throws?

A thrown `AccessControlError` means a fault (usually a misconfiguration), **not**
a normal "denied" — denials return `granted: false`. **Never** let a thrown
error fall through to "allow".

- On the **request path**, use [`tryCan()`](/accesscontrol/best-practices/#can-vs-trycan):
  it never throws — every failure resolves to `granted: false`.
- In **development/tests**, use `can()` so a typo throws loudly.
- Branch on the stable [`err.code`](/accesscontrol/concepts/strict/#error-codes)
  (detect with `AccessControl.isACError(err)`), not on message text.

See [Security Considerations](/accesscontrol/security/) for the full hardening
story.

### Is it production-safe / how is it tested?

Single pinned runtime dependency, zero production advisories
(`npm audit --omit=dev`), 100% coverage, mutation‑tested, plus an adversarial
suite and a property fuzzer. See
[Best Practices › Quality & testing](/accesscontrol/best-practices/#quality--testing).
