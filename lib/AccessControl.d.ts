import { Access, IAccessInfo, Query, IQueryInfo, Permission } from './core';
/**
 *  @classdesc
 *  AccessControl class that implements RBAC (Role-Based Access Control) basics
 *  and ABAC (Attribute-Based Access Control) <i>resource</i> and <i>action</i>
 *  attributes.
 *
 *  Construct an `AccessControl` instance by either passing a grants object (or
 *  array fetched from database) or simply omit `grants` parameter if you are
 *  willing to build it programmatically.
 *
 *  <p><pre><code> const grants = {
 *      role1: {
 *          resource1: {
 *              "create:any": [ attrs ],
 *              "read:own": [ attrs ]
 *          },
 *          resource2: {
 *              "create:any": [ attrs ],
 *              "update:own": [ attrs ]
 *          }
 *      },
 *      role2: { ... }
 *  };
 *  const ac = new AccessControl(grants);</code></pre></p>
 *
 *  The `grants` object can also be an array, such as a flat list
 *  fetched from a database.
 *
 *  <p><pre><code> const flatList = [
 *      { role: 'role1', resource: 'resource1', action: 'create:any', attributes: [ attrs ] },
 *      { role: 'role1', resource: 'resource1', action: 'read:own', attributes: [ attrs ] },
 *      { role: 'role2', ... },
 *      ...
 *  ];</code></pre></p>
 *
 *  We turn this list into a hashtable for better performance. We aggregate
 *  the list by roles first, resources second. If possession (in action
 *  value or as a separate property) is omitted, it will default to `"any"`.
 *  e.g. `"create"` ➞ `"create:any"`
 *
 *  Below are equivalent:
 *  <p><pre><code> const grants = { role: 'role1', resource: 'resource1', action: 'create:any', attributes: [ attrs ] }
 *  const same = { role: 'role1', resource: 'resource1', action: 'create', possession: 'any', attributes: [ attrs ] }</code></pre></p>
 *
 *  So we can also initialize with this flat list of grants:
 *  <p><pre><code> const ac = new AccessControl(flatList);
 *  console.log(ac.getGrants());</code></pre></p>
 *
 *  @author   Onur Yıldırım <onur@cutepilot.com>
 *  @license  MIT
 *
 *  @class
 *  @global
 *
 *  @example
 *  const ac = new AccessControl(grants);
 *
 *  ac.grant('admin').createAny('profile');
 *
 *  // or you can chain methods
 *  ac.grant('admin')
 *      .createAny('profile')
 *      .readAny('profile', ["*", "!password"])
 *      .readAny('video')
 *      .deleteAny('video');
 *
 *  // since these permissions have common resources, there is an alternative way:
 *  ac.grant('admin')
 *      .resource('profile').createAny().readAny(null, ["*", "!password"])
 *      .resource('video').readAny()..deleteAny();
 *
 *  ac.grant('user')
 *      .readOwn('profile', ["uid", "email", "address.*", "account.*", "!account.roles"])
 *      .updateOwn('profile', ["uid", "email", "password", "address.*", "!account.roles"])
 *      .deleteOwn('profile')
 *      .createOwn('video', ["*", "!geo.*"])
 *      .readAny('video')
 *      .updateOwn('video', ["*", "!geo.*"])
 *      .deleteOwn('video');
 *
 *  // now we can check for granted or denied permissions
 *  const permission = ac.can('admin').readAny('profile');
 *  permission.granted // true
 *  permission.attributes // ["*", "!password"]
 *  permission.filter(data) // { uid, email, address, account }
 *  // deny permission
 *  ac.deny('admin').createAny('profile');
 *  ac.can('admin').createAny('profile').granted; // false
 *
 *  // To add a grant but deny access via attributes
 *  ac.grant('admin').createAny('profile', []); // no attributes allowed
 *  ac.can('admin').createAny('profile').granted; // false
 *
 *  // To prevent any more changes:
 *  ac.lock();
 */
declare class AccessControl {
    /**
     *  @private
     */
    private _grants;
    /**
     *  @private
     */
    private _isLocked;
    /**
     *  Initializes a new instance of `AccessControl` with the given grants.
     *  @ignore
     *
     *  @param {Object|Array} [grants] - A list containing the access grant
     *      definitions. See the structure of this object in the examples.
     */
    constructor(grants?: any);
    /**
     *  Specifies whether the underlying grants object is frozen and all
     *  functionality for modifying it is disabled.
     *  @name AccessControl#isLocked
     *  @type {Boolean}
     */
    readonly isLocked: boolean;
    /**
     *  Gets the internal grants object that stores all current grants.
     *
     *  @return {Object} - Hash-map of grants.
     *
     *  @example
     *  ac.grant('admin')
     *      .createAny(['profile', 'video'])
     *      .deleteAny(['profile', 'video'])
     *      .readAny(['video'])
     *      .readAny('profile', ['*', '!password'])
     *      .grant('user')
     *      .readAny(['profile', 'video'], ['*', '!id', '!password'])
     *      .createOwn(['profile', 'video'])
     *      .deleteOwn(['video']);
     *  // logging underlying grants model
     *  console.log(ac.getGrants());
     *  // outputs:
     *  {
     *    "admin": {
     *      "profile": {
     *        "create:any": ["*"],
     *        "delete:any": ["*"],
     *        "read:any": ["*", "!password"]
     *      },
     *      "video": {
     *        "create:any": ["*"],
     *        "delete:any": ["*"],
     *        "read:any": ["*"]
     *      }
     *    },
     *    "user": {
     *      "profile": {
     *        "read:any": ["*", "!id", "!password"],
     *        "create:own": ["*"]
     *      },
     *      "video": {
     *        "read:any": ["*", "!id", "!password"],
     *        "create:own": ["*"],
     *        "delete:own": ["*"]
     *      }
     *    }
     *  }
     */
    getGrants(): any;
    /**
     *  Sets all access grants at once, from an object or array. Note that this
     *  will reset the object and remove all previous grants.
     *  @chainable
     *
     *  @param {Object|Array} grantsObject - A list containing the access grant
     *         definitions.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     *
     *  @throws {AccessControlError} - If called after `.lock()` is called or if
     *  passed grants object fails inspection.
     */
    setGrants(grantsObject: any): AccessControl;
    /**
     *  Resets the internal grants object and removes all previous grants.
     *  @chainable
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     *
     *  @throws {AccessControlError} - If called after `.lock()` is called.
     */
    reset(): AccessControl;
    /**
     *  Freezes the underlying grants model and disables all functionality for
     *  modifying it. This is useful when you want to restrict any changes. Any
     *  attempts to modify (such as `#setGrants()`, `#reset()`, `#grant()`,
     *  `#deny()`, etc) will throw after grants are locked. Note that <b>there
     *  is no `unlock()` method</b>. It's like you lock the door and swallow the
     *  key. ;)
     *
     *  Remember that this does not prevent the `AccessControl` instance from
     *  being altered/replaced. Only the grants inner object is locked.
     *
     *  <b>A note about performance</b>: This uses recursive `Object.freeze()`.
     *  In NodeJS & V8, enumeration performance is not impacted because of this.
     *  In fact, it increases the performance because of V8 optimization.
     *  @chainable
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     *
     *  @example
     *  ac.grant('admin').create('product');
     *  ac.lock(); // called on the AccessControl instance.
     *  // or
     *  ac.grant('admin').create('product').lock(); // called on the chained Access instance.
     *
     *  // After this point, any attempt of modification will throw
     *  ac.setGrants({}); // throws
     *  ac.grant('user'); // throws..
     *  // underlying grants model is not changed
     */
    lock(): AccessControl;
    /**
     *  Extends the given role(s) with privileges of one or more other roles.
     *  @chainable
     *
     *  @param {string|Array<String>} roles Role(s) to be extended. Single role
     *         as a `String` or multiple roles as an `Array`. Note that if a
     *         role does not exist, it will be automatically created.
     *
     *  @param {string|Array<String>} extenderRoles Role(s) to inherit from.
     *         Single role as a `String` or multiple roles as an `Array`. Note
     *         that if a extender role does not exist, it will throw.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     *
     *  @throws {AccessControlError} - If a role is extended by itself or a
     *  non-existent role. Or if called after `.lock()` is called.
     */
    extendRole(roles: string | string[], extenderRoles: string | string[]): AccessControl;
    /**
     *  Removes all the given role(s) and their granted permissions, at once.
     *  @chainable
     *
     *  @param {string|Array<String>} roles - An array of roles to be removed.
     *      Also accepts a string that can be used to remove a single role.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     *
     *  @throws {AccessControlError} - If called after `.lock()` is called.
     */
    removeRoles(roles: string | string[]): AccessControl;
    /**
     *  Removes all the given resources for all roles, at once.
     *  Pass the `roles` argument to remove access to resources for those
     *  roles only.
     *  @chainable
     *
     *  @param {string|Array<String>} resources - A single or array of resources to
     *      be removed.
     *  @param {string|Array<String>} [roles] - A single or array of roles to
     *      be removed. If omitted, permissions for all roles to all given
     *      resources will be removed.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     *
     *  @throws {AccessControlError} - If called after `.lock()` is called.
     */
    removeResources(resources: string | string[], roles?: string | string[]): AccessControl;
    /**
     *  Gets all the unique roles that have at least one access information.
     *
     *  @returns {Array<String>}
     *
     *  @example
     *  ac.grant('admin, user').createAny('video').grant('user').readOwn('profile');
     *  console.log(ac.getRoles()); // ["admin", "user"]
     */
    getRoles(): string[];
    /**
     *  Gets the list of inherited roles by the given role.
     *  @name AccessControl#getInheritedRolesOf
     *  @alias AccessControl#getExtendedRolesOf
     *  @function
     *
     *  @param {string} role - Target role name.
     *
     *  @returns {Array<String>}
     */
    getInheritedRolesOf(role: string): string[];
    /**
     *  Alias of `getInheritedRolesOf`
     *  @private
     */
    getExtendedRolesOf(role: string): string[];
    /**
     *  Gets all the unique resources that are granted access for at
     *  least one role.
     *
     *  @returns {Array<String>}
     */
    getResources(): string[];
    /**
     *  Checks whether the grants include the given role or roles.
     *
     *  @param {string|string[]} role - Role to be checked. You can also pass an
     *  array of strings to check multiple roles at once.
     *
     *  @returns {Boolean}
     */
    hasRole(role: string | string[]): boolean;
    /**
     *  Checks whether grants include the given resource or resources.
     *
     *  @param {string|string[]} resource - Resource to be checked. You can also pass an
     *  array of strings to check multiple resources at once.
     *
     *  @returns {Boolean}
     */
    hasResource(resource: string | string[]): boolean;
    /**
     *  Gets an instance of `Query` object. This is used to check whether the
     *  defined access is allowed for the given role(s) and resource. This
     *  object provides chainable methods to define and query the access
     *  permissions to be checked.
     *  @name AccessControl#can
     *  @alias AccessControl#query
     *  @function
     *  @chainable
     *
     *  @param {string|Array|IQueryInfo} role - A single role (as a string), a
     *  list of roles (as an array) or an
     *  {@link ?api=ac#AccessControl~IQueryInfo|`IQueryInfo` object} that fully
     *  or partially defines the access to be checked.
     *
     *  @returns {Query} - The returned object provides chainable methods to
     *  define and query the access permissions to be checked. See
     *  {@link ?api=ac#AccessControl~Query|`Query` inner class}.
     *
     *  @example
     *  const ac = new AccessControl(grants);
     *
     *  ac.can('admin').createAny('profile');
     *  // equivalent to:
     *  ac.can().role('admin').createAny('profile');
     *  // equivalent to:
     *  ac.can().role('admin').resource('profile').createAny();
     *
     *  // To check for multiple roles:
     *  ac.can(['admin', 'user']).createOwn('profile');
     *  // Note: when multiple roles checked, acquired attributes are unioned (merged).
     */
    can(role: string | string[] | IQueryInfo): Query;
    /**
     *  Alias of `can()`.
     *  @private
     */
    query(role: string | string[] | IQueryInfo): Query;
    /**
     *  Gets an instance of `Permission` object that checks and defines the
     *  granted access permissions for the target resource and role. Normally
     *  you would use `AccessControl#can()` method to check for permissions but
     *  this is useful if you need to check at once by passing a `IQueryInfo`
     *  object; instead of chaining methods (as in
     *  `.can(<role>).<action>(<resource>)`).
     *
     *  @param {IQueryInfo} queryInfo - A fulfilled
     *  {@link ?api=ac#AccessControl~IQueryInfo|`IQueryInfo` object}.
     *
     *  @returns {Permission} - An object that provides properties and methods
     *  that defines the granted access permissions. See
     *  {@link ?api=ac#AccessControl~Permission|`Permission` inner class}.
     *
     *  @example
     *  const ac = new AccessControl(grants);
     *  const permission = ac.permission({
     *      role: "user",
     *      action: "update:own",
     *      resource: "profile"
     *  });
     *  permission.granted; // Boolean
     *  permission.attributes; // Array e.g. [ 'username', 'password', 'company.*']
     *  permission.filter(object); // { username, password, company: { name, address, ... } }
     */
    permission(queryInfo: IQueryInfo): Permission;
    /**
     *  Gets an instance of `Grant` (inner) object. This is used to grant access
     *  to specified resource(s) for the given role(s).
     *  @name AccessControl#grant
     *  @alias AccessControl#allow
     *  @function
     *  @chainable
     *
     *  @param {string|Array<String>|IAccessInfo} [role] A single role (as a
     *  string), a list of roles (as an array) or an
     *  {@link ?api=ac#AccessControl~IAccessInfo|`IAccessInfo` object} that
     *  fully or partially defines the access to be granted. This can be omitted
     *  and chained with `.role()` to define the role.
     *
     *  @return {Access} - The returned object provides chainable properties to
     *  build and define the access to be granted. See the examples for details.
     *  See {@link ?api=ac#AccessControl~Access|`Access` inner class}.
     *
     *  @throws {AccessControlError} - If `role` is explicitly set to an invalid value.
     *  @throws {AccessControlError} - If called after `.lock()` is called.
     *
     *  @example
     *  const ac = new AccessControl();
     *  let attributes = ['*'];
     *
     *  ac.grant('admin').createAny('profile', attributes);
     *  // equivalent to:
     *  ac.grant().role('admin').createAny('profile', attributes);
     *  // equivalent to:
     *  ac.grant().role('admin').resource('profile').createAny(null, attributes);
     *  // equivalent to:
     *  ac.grant({
     *      role: 'admin',
     *      resource: 'profile',
     *  }).createAny(null, attributes);
     *  // equivalent to:
     *  ac.grant({
     *      role: 'admin',
     *      resource: 'profile',
     *      action: 'create:any',
     *      attributes: attributes
     *  });
     *  // equivalent to:
     *  ac.grant({
     *      role: 'admin',
     *      resource: 'profile',
     *      action: 'create',
     *      possession: 'any', // omitting this will default to 'any'
     *      attributes: attributes
     *  });
     *
     *  // To grant same resource and attributes for multiple roles:
     *  ac.grant(['admin', 'user']).createOwn('profile', attributes);
     *
     *  // Note: when attributes is omitted, it will default to `['*']`
     *  // which means all attributes (of the resource) are allowed.
     */
    grant(role?: string | string[] | IAccessInfo): Access;
    /**
     *  Alias of `grant()`.
     *  @private
     */
    allow(role?: string | string[] | IAccessInfo): Access;
    /**
     *  Gets an instance of `Access` object. This is used to deny access to
     *  specified resource(s) for the given role(s). Denying will only remove a
     *  previously created grant. So if not granted before, you don't need to
     *  deny an access.
     *  @name AccessControl#deny
     *  @alias AccessControl#reject
     *  @function
     *  @chainable
     *
     *  @param {string|Array<String>|IAccessInfo} role A single role (as a
     *  string), a list of roles (as an array) or an
     *  {@link ?api=ac#AccessControl~IAccessInfo|`IAccessInfo` object} that
     *  fully or partially defines the access to be denied.
     *
     *  @return {Access} The returned object provides chainable properties to
     *  build and define the access to be granted. See
     *  {@link ?api=ac#AccessControl~Access|`Access` inner class}.
     *
     *  @throws {AccessControlError} - If `role` is explicitly set to an invalid value.
     *  @throws {AccessControlError} - If called after `.lock()` is called.
     *
     *  @example
     *  const ac = new AccessControl();
     *
     *  ac.deny('admin').createAny('profile');
     *  // equivalent to:
     *  ac.deny().role('admin').createAny('profile');
     *  // equivalent to:
     *  ac.deny().role('admin').resource('profile').createAny();
     *  // equivalent to:
     *  ac.deny({
     *      role: 'admin',
     *      resource: 'profile',
     *  }).createAny();
     *  // equivalent to:
     *  ac.deny({
     *      role: 'admin',
     *      resource: 'profile',
     *      action: 'create:any'
     *  });
     *  // equivalent to:
     *  ac.deny({
     *      role: 'admin',
     *      resource: 'profile',
     *      action: 'create',
     *      possession: 'any' // omitting this will default to 'any'
     *  });
     *
     *  // To deny same resource for multiple roles:
     *  ac.deny(['admin', 'user']).createOwn('profile');
     */
    deny(role?: string | string[] | IAccessInfo): Access;
    /**
     *  Alias of `deny()`.
     *  @private
     */
    reject(role?: string | string[] | IAccessInfo): Access;
    /**
     *  @private
     */
    _removePermission(resources: string | string[], roles?: string | string[], actionPossession?: string): void;
    /**
     *  Documented separately in enums/Action
     *  @private
     */
    static readonly Action: any;
    /**
     *  Documented separately in enums/Possession
     *  @private
     */
    static readonly Possession: any;
    /**
     *  Documented separately in AccessControlError
     *  @private
     */
    static readonly Error: any;
    /**
     *  A utility method for deep cloning the given data object(s) while
     *  filtering its properties by the given attribute (glob) notations.
     *  Includes all matched properties and removes the rest.
     *
     *  Note that this should be used to manipulate data / arbitrary objects
     *  with enumerable properties. It will not deal with preserving the
     *  prototype-chain of the given object.
     *
     *  @param {Object|Array} data - A single or array of data objects
     *      to be filtered.
     *  @param {Array|String} attributes - The attribute glob notation(s)
     *      to be processed. You can use wildcard stars (*) and negate
     *      the notation by prepending a bang (!). A negated notation
     *      will be excluded. Order of the globs do not matter, they will
     *      be logically sorted. Loose globs will be processed first and
     *      verbose globs or normal notations will be processed last.
     *      e.g. `[ "car.model", "*", "!car.*" ]`
     *      will be sorted as:
     *      `[ "*", "!car.*", "car.model" ]`.
     *      Passing no parameters or passing an empty string (`""` or `[""]`)
     *      will empty the source object.
     *
     *  @returns {Object|Array} - Returns the filtered data object or array
     *      of data objects.
     *
     *  @example
     *  var assets = { notebook: "Mac", car: { brand: "Ford", model: "Mustang", year: 1970, color: "red" } };
     *
     *  var filtered = AccessControl.filter(assets, [ "*", "!car.*", "car.model" ]);
     *  console.log(assets); // { notebook: "Mac", car: { model: "Mustang" } }
     *
     *  filtered = AccessControl.filter(assets, "*"); // or AccessControl.filter(assets, ["*"]);
     *  console.log(assets); // { notebook: "Mac", car: { model: "Mustang" } }
     *
     *  filtered = AccessControl.filter(assets); // or AccessControl.filter(assets, "");
     *  console.log(assets); // {}
     */
    static filter(data: any, attributes: string[]): any;
    /**
     *  Checks whether the given object is an instance of `AccessControl.Error`.
     *  @name AccessControl.isACError
     *  @alias AccessControl.isAccessControlError
     *  @function
     *
     *  @param {Any} object
     *         Object to be checked.
     *
     *  @returns {Boolean}
     */
    static isACError(object: any): boolean;
    /**
     *  Alias of `isACError`
     *  @private
     */
    static isAccessControlError(object: any): boolean;
}
export { AccessControl };
