## AccessControl - Change Log

### **v1.5.1** (2017-05-24)

- Fixed TS import issue. Use `import { AccessControl } from 'accesscontrol'` in TypeScript projects.

### **v1.5.0** (2017-03-08)

- Migrated whole code base to TypeScript.
- More strict validation checks. It will now throw on invalid information passed for both grants and permission checks. This helps prevent typos, unintended permission checks, etc...
- Fixed a bug where checking permission with multiple roles would mutate the permission attributes. Fixes [issue #2](https://github.com/onury/accesscontrol/issues/2).
- When an access definition object (`IAccessInfo` instead of role(s)) passed to `.grant()` or `.deny()` methods, it's no longer mutated.
- You could grant permissions for multiple roles at once. Now, you can also grant permissions for multiple resources at the same time. This is very handy when you permit _all attributes_ of the resources; e.g. `ac.grant(['admin', 'superadmin']).readAny(['account', 'video'], ['*'])`. The caveat is that the resources (most probably) have different attributes; so you can either permit all, or only common attributes (e.g. `['id', 'name']`).
- Extending a role with a non-existent role will now throw.

### **v1.0.1** (2016-11-09)

- Permission filter would throw an error due to syntax. Fixes [issue #1](https://github.com/onury/accesscontrol/issues/1).
- (Dev) added filter test.

### **v1.0.0** (2016-09-10)

- initial release.
