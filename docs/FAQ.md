## Frequently Asked Questions
---

> _This FAQ provides general information about the term "Access Control" but most definitions are specific to AccessControl.js - how the library is implemented._

### What is "Access Control"?

In information security, **Access Control** is selective restriction of **_access_** to a **_resource_**. 

AccessControl.js ...
- defines act of accessing by "actions".
- provides an abstract layer between the application logic and the requested resource and action. 

### What is an "action"?

AccessControl.js defines "accessing" by [CRUD][crud] actions (`create`, `read`, `update`, `delete`). It does not specify **how an _action_ is performed** on the _resource_.  But rather, decides **whether the _action_ can be performed** by the accessing party: **_role_**.

Below is a typical match of AC actions to actual HTTP and database operations:

| AccessControl.js | REST/HTTP         | Database|
| ---------------- | ----------------- | --------|  
| **`CREATE`**     | `POST`            | `INSERT`|  
| **`READ`**       | `GET`             | `SELECT`|  
| **`UPDATE`**     | `PUT` or `PATCH`  | `UPDATE`|  
| **`DELETE`**     | `DELETE`          | `DELETE`|  

Most of the time this might be the case; but depending on the context or resource; you could map these actions to completely different operations.

- a **`CREATE`** might mean sending an SMS to a user.
- a **`READ`** might mean downloading a file.
- a **`DELETE`** in AccessControl logic might mean an **`UPDATE`** in database.  
e.g. setting a table field, named `isDeleted` to `1` (soft-delete).

and so on...

### What is a "resource"?

A **resource** identifies a unique thing (noun) that's named/referenced and being accessed. This is typically an abstract definition. What the resource actually is; and how that resource is implemented is a **design decision**, the developer makes. 

Depending on the context; a resource can be a _document_, a _database record_, an _apple_, the _relationship of two people_, _fear of dark_, a _cat breed_, a _cat_, [etc...][res-examples]

When defining a resource for AccessControl, the developer should decide whether that _"thing"_...
- is semantically unique (different than other defined resources),
- requires a distinguished control of access. 

For example:
- We have a database table called `accounts`.
- The `accounts` table has fields such as `firstName`, `lastName`, `email` and `pwd`.
- In our application context, a user can modify `firstName` and `lastName` freely. But we'll have a separate page for changing the password and/or email address; which will prompt for current password.

In this scenario, we may have two resources: `account` and `credentials`
```js
ac.grant('user')
  .createAny('account')                           // create new account with all attributes
  .updateOwn('account', ['*', '!pwd', '!email'])  // update own account except password and email
  .updateOwn('credentials')                       // update own credentials (password and email)
```

### How do you define a resource?

In AccessControl.js, a resource is defined whenever a permission is granted or denied for the first time, for that resource.

```js
ac.can('monkey').createOwn('banana').granted   // false
ac.hasResource('banana');                      // false
ac.grant('monkey').createOwn('banana');        // resource is defined for the first time
ac.hasResource('banana');                      // true
ac.can('monkey').createOwn('banana').granted   // true
```

### Can I use AccessControl.js with a database? How?
(MySQL,  PostgreSQL, MongoDB, etc..)

AccessControl.js is not coupled with any kind of database system. Actually it's unrelated. It only grants or denies access to a resource. The rest depends on your application's logic and decisions you (the developer) make.

Here is a scenario;
- Application logic: _"Users can assign folders to users."_  
In the backend, this is done by creating a record in a relational  table: `folderUsers` 
- So, we have 3 tables in our database:  `users`, `folders` and `folderUsers` 
- The relation is established by two fields, in `folderUsers` table:
  - `folderId` ( foreign-key: `folders.id` )
  - `userId` ( foreign-key: `users.id` )  

- In AccessControl, we'll represent this resource as `"fu-relation"`.  
And we'll restrict access for `create` actions performed on this resource.

In this case, we have 4 options.  

By **creating** a **`fu-relation`** resource, **a user of this role**, can assign...

| # | Permission                                     | covers |
| - | -----------------------------------------------| -------|
| 1 | ... **own** `folder` to itself (**own** `user`)|        |
| 2 | ... **any** `folder` to itself (**own** `user`)| 1      |
| 3 | ... **own** `folder` to **any** `user`         | 1      |
| 4 | ... **any** `folder` to **any** `user`         | 1, 2, 3|

When you grant or check for a permission via `.createOwn()`, you (the developer) should decide what **_own_** stands for.  So I will make the following **decision** as the developer.  

In **this context**:
- **own** `fu-relation` means _"**own** `folder` to **any** `user`"_ (option # 3)
- **any** `fu-relation` means _"**any** `folder` to **any** `user`"_ (option #4)

With this **decision**:
- I don't need to check whether the assigned-user is current (_own_) user. 
- I need to check whether the assigned-folder is _own_ `folder` (implied resource) of the current user.

First I'll define 2 roles; `user` and `admin`; and grant access permissions accordingly:
```js
ac.grant('user').createOwn('fu-relation')
  .grant('admin').createAny('fu-relation');
```
So when the resource is accessed, I'll check these permissions, and restrict or allow the request:
```js
// psuedo (sync) code

var role = session.role; // role of the requesting user: 'user' or 'admin'
var userIdToBeAssigned = request.params.userId; // can be any user id
var folderId = request.params.folderId;

// First check if current role can create "ANY" fu-relation. (ANY > OWN)
var permission = ac.can(role).createAny('fu-relation');

// if not granted, check if current role can create "OWN" fu-relation:
if (permission.granted === false) {
    // Determine whether the implied resource (folder) is "owned" 
    // by the current user. This is app's responsibility, not AC's.
    if (session.userId === getFolder(folderId).userId) {
        // We made sure that the implied resource is "owned" by this user.
        // Now we can ask AccessControl permission for performing 
        // the action on the target resource:
        permission = ac.can(role).createOwn('fu-relation');
    }
}

// Finally, execute the operation if allowed:
if (permission.granted) {
    // whatever app-logic here.. e.g.:
    db.insert({ 
        table: folderUsers,
        row: { 
            folderId: request.params.folderId, 
            userId: userIdToBeAssigned
        }
    });  
} else {
    // forbidden
    console.log('Access Denied!');
}
```

### What to do when AccessControl.js throws an error?

Granting permissions for valuable resources and managing access levels for user roles... This is a highly sensitive context; in which mostly, any failure or exception becomes critical. So in any case, an `AccessControlError` is thrown right away. **No silent errors**!

**In Development:**
Hard-test your application with all or most possible use cases, in terms of access management and control. If you see any `AccessControlError` thrown you should definitely fix it immediately. Because this typically indicates that your grants model either has a logical or technical flaw.

**In Production:**
You did all your tests in development but still, if a caught exception is an instance of `AccessControlError`, I highly recommend the host application should be gracefully shut down when in production.  

For details on errors thrown, see [AccessControl Errors][errors] section.


[errors]:http://onury.io/accesscontrol/?content=errors
[ac]:https://en.wikipedia.org/wiki/Access_control
[crud]:https://en.wikipedia.org/wiki/Create,_read,_update_and_delete
[res-examples]:http://stackoverflow.com/a/10883810/112731
