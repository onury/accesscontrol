## AccessControl - Change Log

### v2.2.1 (2018-02-24)

- **Fixed** an issue with attribute filtering caused by the core dependency Notation. Now [fixed](https://github.com/onury/notation/issues/7) and updated.
- **(Dev)** Updated dev-dependencies to latest versions. Removed yarn.

### v2.2.0 (2017-11-25)

**This release greatly improves stability!**

- **Fixed** an issue where action and possession of a permission query is not pre-normalized. Only   `#permission()` method was affected.
- **Fixed** an issue where it would throw even if `$extend` was used properly in the initial grants model, passed to the constructor or `#setGrants()`. Fixes [issue #22](https://github.com/onury/accesscontrol/issues/22).
- **Fixed** a memory leak (leading to "maximum call stack" error) occurs while processing role hierarchy.
- **Fixed** an issue where role validation would incorrectly return `true` in a specific case.
- **Revised** `#lock()` to throw a meaningful error if not successful.
- **Revised** `#hasRole()` and `#hasResource()` methods to also accept a string array (to check for multiple at once), in addition to `string` (single).
- **Revised** various chain methods to throw when explicit invalid values are passed. e.g. `ac.grant()...` will not throw (omitted parameter allowed) but `ac.grant(undefined)...` will throw. This mitigates the chance of passing an unset variable by mistake.
- Various revisions, optimizations and clean-up.
- **(Dev)** Migrated tests to Jest. Refactored tests to TypeScript. Removed Jasmine and dependencies. 
- **(Dev)** Adapted `yarn`. Enabled test coverage via `jest`. Added `coveralls` support.
- **(Dev)** Added moooore tests. Revised code style. Improved coverage.

### v2.0.0 (2017-10-05)

- **Breaking-Change**: Cross role inheritance is no more allowed. Fixes [issue #18](https://github.com/onury/accesscontrol/issues/18).
- **Breaking-Change**: Grants model cannot be emptied any more by omitting the parameter (e.g. `#setGrants()`) or passing `null`, `undefined`. This will throw. You need to either, explicitly call `#reset()` or set grants to an empty object (`{}`) in order to reset/empty grants safely. 
- **Breaking-Change**: Renamed `#access()` to `#query()`. This is an alias for `#can()` method.  
- **Fixed** an issue where deeper inherited roles (more than 1 level) would not be taken into account while querying for permissions. Fixes [issue #17](https://github.com/onury/accesscontrol/issues/17).
- **Added** `AccessControl#lock()` method that freezes the underlying grants model and disables all functionality for modifying it. This is useful when you want to restrict any changes. Any attempts to modify (such as `#setGrants()`, `#grant()`, `#deny()`, etc) will throw after grants are locked. There is no `unlock()` method. It's like you lock the door and swallow the key. :yum:
- **Added** `AccessControl#isLocked` `boolean` property.
- **Added** `AccessControl#getInheritedRolesOf()` convenience method.
- **Fixed** a mutation issue occurred when resource attributes are unioned. ([Notation issue #2][notation-issue-2]).
- **Fixed** an issue with unioned attributes (when a role extends another and attributes (globs) are unioned for querying permissions). Fixes [issue #19](https://github.com/onury/accesscontrol/issues/19) ([Notation issue #3][notation-issue-3]).
- **Added** the ability to detect invalid grants object passed to `AccessControl` instance. In order to prevent silent, future errors and mistakes; `AccessControl` now thoroughly inspects the grants object passed to constructor or `#setGrants()` method; and throws immediately if it has an invalid structure or configuration.
- **Revised** `AccessControl` to throw if any reserved keywords are used (i.e. for role, resource names) such as `"$"`, `"$extend"`.
- **Added** the ability to parse comma-separated attributes. You can now use this, in addition to string arrays; for defining resource attributes.

### v1.5.4 (2017-09-22)

- **Fixed** an issue where the static method `AccessControl.filter()` does not return the filtered data properly. Fixes [issue #16](https://github.com/onury/accesscontrol/issues/16).

### v1.5.3 (2017-08-25)

- **Improvement**: Errors are now thrown with more [meaningful messages](https://github.com/onury/accesscontrol/issues/13#issuecomment-324755478).

### v1.5.2 (2017-07-02)

- **Fixed** an issue where the grants were not processed into the inner grants model structure; if an array is passed to `AccessControl` constructor; instead of using `.setGrants()`. Fixes [issue #10](https://github.com/onury/accesscontrol/issues/10).

### v1.5.1 (2017-05-24)

- **Fixed** TS import issue. Use `import { AccessControl } from 'accesscontrol'` in TypeScript projects.

### v1.5.0 (2017-03-08)

- **Improvement**: Migrated whole code base to TypeScript.
- **Added** more strict validation checks. It will now throw on invalid information passed for both grants and permission checks. This helps prevent typos, unintended permission checks, etc...
- **Fixed** a bug where checking permission with multiple roles would mutate the permission attributes. Fixes [issue #2](https://github.com/onury/accesscontrol/issues/2).
- **Fixed** a mutation issue when an access definition object (`IAccessInfo` instead of role(s)) passed to `.grant()` or `.deny()` methods.
- **Improvement**: You could grant permissions for multiple roles at once. Now, you can also grant permissions for multiple resources at the same time. This is very handy when you permit _all attributes_ of the resources; e.g. `ac.grant(['admin', 'superadmin']).readAny(['account', 'video'], ['*'])`. The caveat is that the resources (most probably) have different attributes; so you can either permit all, or only common attributes (e.g. `['id', 'name']`).
- **Improvement**: Extending a role with a non-existent role will now throw.

### v1.0.1 (2016-11-09)

- **Fixed** a syntax issue that throws when permission filter is called. Fixes [issue #1](https://github.com/onury/accesscontrol/issues/1).
- (Dev) added filter test.

### v1.0.0 (2016-09-10)

- initial release.


[notation]:https://github.com/onury/notation
[notation-issue-2]:https://github.com/onury/notation/issues/2
[notation-issue-3]:https://github.com/onury/notation/issues/3
