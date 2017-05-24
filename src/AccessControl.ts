import { Access, IAccessInfo, Query, IQueryInfo, Permission, AccessControlError } from './core';
import { Action, Possession, actions, possessions } from './enums';
import utils from './utils';

/**
 *  @classdesc
 *  AccessControl class that implements RBAC (Role-Based Access Control) basics
 *  and ABAC (Attribute-Based Access Control) <i>resource</i> and <i>action</i>
 *  attributes.
 *
 *  Construct an `AccessControl` instance by either passing a grants object (or
 *  array fetched from database) or simple omit `grants` parameter if you are
 *  willing to build it programmatically.
 *
 *  <p><pre><code> var grants = {
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
 *  var ac = new AccessControl(grants);</code></pre></p>
 *
 *  The `grants` object can also be an array, such as a flat list
 *  fetched from a database.
 *
 *  <p><pre><code> var flatList = [
 *      { role: "role1", resource: "resource1", action: "create:any", attributes: [ attrs ] },
 *      { role: "role1", resource: "resource1", action: "read:own", attributes: [ attrs ] },
 *      { role: "role2", ... },
 *      ...
 *  ];</code></pre></p>
 *
 *  We turn this list into a hashtable for better performance. We aggregate
 *  the list by roles first, resources second. If possession (in action
 *  value or as a separate property) is omitted, it will default to `"any"`.
 *  e.g. `"create"` —> `"create:any"`
 *
 *  Below are equivalent:
 *  <p><pre><code> var grants = { role: "role1", resource: "resource1", action: "create:any", attributes: [ attrs ] }
 *  var same = { role: "role1", resource: "resource1", action: "create", possession: "any", attributes: [ attrs ] }</code></pre></p>
 *
 *  So we can also initialize with this flat list of grants:
 *  <p><pre><code> var ac = new AccessControl(flatList);
 *  console.log(ac.getGrants());</code></pre></p>
 *
 *  @author   Onur Yıldırım (onur@cutepilot.com)
 *  @license  MIT
 *
 *  @class
 *  @global
 *
 *  @example
 *  var ac = new AccessControl(grants);
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
 *  var permission = ac.can('admin').readAny('profile');
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
 */
class AccessControl {

    /**
     *  @private
     */
    private _grants:any;

    /**
     *  Initializes a new instance of `AccessControl` with the given grants.
     *  @ignore
     *
     *  @param {Object|Array} grants - A list containing the access grant
     *      definitions. See the structure of this object in the examples.
     */
    constructor(grants:any = {}) {
        this._grants = grants;
    }

    // -------------------------------
    //  PUBLIC METHODS
    // -------------------------------

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
    getGrants():any {
        return this._grants;
    }

    /**
     *  Sets all access grants at once, from an object or array.
     *  Note that this will reset the object and remove all previous grants.
     *  @chainable
     *
     *  @param {Object|Array} grantsObject - A list containing the access grant
     *         definitions.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     */
    setGrants(grantsObject:any):AccessControl {
        this._grants = {};
        let type:string = utils.type(grantsObject);
        if (type === 'object') {
            this._grants = grantsObject;
        } else if (type === 'array') {
            grantsObject.forEach((item:any) => utils.commitToGrants(this._grants, item, true));
        }
        return this;
    }

    /**
     *  Resets the internal grants object and removes all previous grants.
     *  @chainable
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     */
    reset():AccessControl {
        this._grants = {};
        return this;
    }

    /**
     *  Extends the given role(s) with privileges of one or more other roles.
     *  @chainable
     *
     *  @param {String|Array<String>} roles
     *         Role(s) to be extended.
     *         Single role as a `String` or multiple roles as an `Array`.
     *         Note that if a role does not exist, it will be automatically
     *         created.
     *
     *  @param {String|Array<String>} extenderRoles
     *         Role(s) to inherit from.
     *         Single role as a `String` or multiple roles as an `Array`.
     *         Note that if a extender role does not exist, it will throw.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     *
     *  @throws {Error}
     *          If a role is extended by itself or a non-existent role.
     */
    extendRole(roles:string|string[], extenderRoles:string|string[]):AccessControl {
        utils.extendRole(this._grants, roles, extenderRoles);
        return this;
    }

    /**
     *  Removes all the given role(s) and their granted permissions, at once.
     *  @chainable
     *
     *  @param {String|Array<String>} roles - An array of roles to be removed.
     *      Also accepts a string that can be used to remove a single role.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     */
    removeRoles(roles:string|string[]):AccessControl {
        let rolesToRemove:string[] = utils.toStringArray(roles);
        rolesToRemove.forEach((role:string) => {
            delete this._grants[role];
        });
        // also remove these roles from $extend list of each remaining role.
        this._each((role:string, roleItem:any) => {
            if (Array.isArray(roleItem.$extend)) {
                roleItem.$extend = utils.subtractArray(roleItem.$extend, rolesToRemove);
            }
        });
        return this;
    }

    /**
     *  Removes all the given resources for all roles, at once.
     *  Pass the `roles` argument to remove access to resources for those
     *  roles only.
     *  @chainable
     *
     *  @param {String|Array<String>} resources - A single or array of resources to
     *      be removed.
     *  @param {String|Array<String>} [roles] - A single or array of roles to
     *      be removed. If omitted, permissions for all roles to all given
     *      resources will be removed.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     */
    removeResources(resources:string|string[], roles?:string|string[]):AccessControl {
        // _removePermission has a third argument `actionPossession`. if
        // omitted (like below), removes the parent resource object.
        this._removePermission(resources, roles);
        return this;
    }

    /**
     *  Gets all the unique roles that have at least one access information.
     *
     *  @returns {Array<String>}
     *
     *  @example
     *  ac.grant('admin, user').createAny('video').grant('user').readOwn('profile');
     *  console.log(ac.getRoles()); // ["admin", "user"]
     */
    getRoles():string[] {
        return Object.keys(this._grants);
    }

    /**
     *  Gets all the unique resources that are granted access for at
     *  least one role.
     *
     *  @returns {Array<String>}
     */
    getResources():string[] {
        // using an object for unique list
        let resources:any = {};
        this._eachRoleResource((role:string, resource:string, permissions:any) => {
            resources[resource] = null;
        });
        return Object.keys(resources);
    }

    /**
     *  Checks whether any permissions are granted to the given role.
     *
     *  @param {String} role - Role to be checked.
     *
     *  @returns {Boolean}
     */
    hasRole(role:string):boolean {
        return this._grants.hasOwnProperty(role);
    }

    /**
     *  Checks whether any permissions are granted for the given resource.
     *
     *  @param {String} resource - Resource to be checked.
     *
     *  @returns {Boolean}
     */
    hasResource(resource:string):boolean {
        if (typeof resource !== 'string' || resource === '') {
            return false;
        }
        let resources = this.getResources();
        return resources.indexOf(resource) >= 0;
    }

    /**
     *  Gets an instance of `Query` object. This is used to check whether
     *  the defined access is allowed for the given role(s) and resource.
     *  This object provides chainable methods to define and query the access
     *  permissions to be checked.
     *  @name AccessControl#can
     *  @alias AccessControl#access
     *  @function
     *  @chainable
     *
     *  @param {String|Array|IQueryInfo} role - A single role (as a string),
     *      a list of roles (as an array) or an {@link ?api=ac#AccessControl~IQueryInfo|`IQueryInfo` object}
     *      that fully or partially defines the access to be checked.
     *
     *  @returns {Query} - The returned object provides chainable
     *      methods to define and query the access permissions to be checked.
     *      See {@link ?api=ac#AccessControl~Query|`Query` inner class}.
     *
     *  @example
     *  var ac = new AccessControl(grants);
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
    can(role:string|string[]|IQueryInfo):Query {
        return new Query(this._grants, role);
    }

    /**
     *  Alias of `can()`.
     *  @private
     */
    access(role:string|string[]|IQueryInfo):Query {
        return this.can(role);
    }

    /**
     *  Gets an instance of `Permission` object that checks and defines
     *  the granted access permissions for the target resource and role.
     *  Normally you would use `AccessControl#can()` method to check for
     *  permissions but this is useful if you need to check at once by passing
     *  a `IQueryInfo` object; instead of chaining methods
     *  (as in `.can(<role>).<action>(<resource>)`).
     *
     *  @param {IQueryInfo} queryInfo
     *         A fulfilled {@link ?api=ac#AccessControl~IQueryInfo|`IQueryInfo` object}.
     *
     *  @returns {Permission} - An object that provides properties
     *  and methods that defines the granted access permissions. See
     *  {@link ?api=ac#AccessControl~Permission|`Permission` inner class}.
     *
     *  @example
     *  var ac = new AccessControl(grants);
     *  var permission = ac.permission({
     *      role: "user",
     *      action: "update:own",
     *      resource: "profile"
     *  });
     *  permission.granted; // Boolean
     *  permission.attributes; // Array e.g. [ 'username', 'password', 'company.*']
     *  permission.filter(object); // { username, password, company: { name, address, ... } }
     */
     permission(queryInfo:IQueryInfo):Permission {
         return new Permission(this._grants, queryInfo);
     }

    /**
     *  Gets an instance of `Grant` (inner) object. This is used to grant access
     *  to specified resource(s) for the given role(s).
     *  @name AccessControl#grant
     *  @alias AccessControl#allow
     *  @function
     *  @chainable
     *
     *  @param {String|Array<String>|IAccessInfo} role
     *         A single role (as a string), a list of roles (as an array) or an
     *         {@link ?api=ac#AccessControl~IAccessInfo|`IAccessInfo` object}
     *         that fully or partially defines the access to be granted.
     *
     *  @return {Access}
     *          The returned object provides chainable properties to build and
     *          define the access to be granted. See the examples for details.
     *          See {@link ?api=ac#AccessControl~Access|`Access` inner class}.
     *
     *  @example
     *  var ac = new AccessControl(),
     *      attributes = ['*'];
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
    grant(role:string|string[]|IAccessInfo):Access {
        return new Access(this._grants, role, false);
    }

    /**
     *  Alias of `grant()`.
     *  @private
     */
    allow(role:string|string[]|IAccessInfo):Access {
        return this.grant(role);
    }

    /**
     *  Gets an instance of `Access` object. This is used to deny access
     *  to specified resource(s) for the given role(s). Denying will only remove
     *  a previously created grant. So if not granted before, you don't need
     *  to deny an access.
     *  @name AccessControl#deny
     *  @alias AccessControl#reject
     *  @function
     *  @chainable
     *
     *  @param {String|Array<String>|IAccessInfo} role
     *         A single role (as a string), a list of roles (as an array) or an
     *         {@link ?api=ac#AccessControl~IAccessInfo|`IAccessInfo` object}
     *         that fully or partially defines the access to be denied.
     *
     *  @return {Access}
     *          The returned object provides chainable properties to build and
     *          define the access to be granted.
     *          See {@link ?api=ac#AccessControl~Access|`Access` inner class}.
     *
     *  @example
     *  var ac = new AccessControl();
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
    deny(role:string|string[]|IAccessInfo):Access {
         return new Access(this._grants, role, true);
    }

    /**
     *  Alias of `deny()`.
     *  @private
     */
    reject(role:string|string[]|IAccessInfo):Access {
        return this.deny(role);
    }

    // -------------------------------
    //  PRIVATE METHODS
    // -------------------------------

    /**
     *  @private
     */
    private _each(callback:(role:string, roleDefinition:any) => void) {
        utils.eachKey(this._grants, (role:string) => callback(role, this._grants[role]));
    }

    /**
     *  @private
     */
    private _eachRole(callback:(role:string) => void) {
        utils.eachKey(this._grants, (role:string) => callback(role));
    }

    /**
     *  @private
     */
    private _eachRoleResource(callback:(role:string, resource:string, resourceDefinition:any) => void) {
        let resources, resourceDefinition;
        this._eachRole((role:string) => {
            resources = this._grants[role];
            utils.eachKey(resources, (resource:string) => {
                resourceDefinition = role[resource];
                callback(role, resource, resourceDefinition);
            });
        });
    }

    /**
     *  @private
     */
    _removePermission(resources:string|string[], roles?:string|string[], actionPossession?:string) {
        resources = utils.toStringArray(resources);
        if (roles) roles = utils.toStringArray(roles);
        this._eachRoleResource((role:string, resource:string, permissions:any) => {
            if (resources.indexOf(resource) >= 0
                    // roles is optional. so remove if role is not defined.
                    // if defined, check if the current role is in the list.
                    && (!roles || roles.indexOf(role) >= 0)) {
                if (actionPossession) {
                    delete this._grants[role][resource][actionPossession];
                } else {
                    // this is used for AccessControl#removeResources().
                    delete this._grants[role][resource];
                }
            }
        });
    }

    // -------------------------------
    //  PUBLIC STATIC PROPERTIES
    // -------------------------------

    /**
     *  Documented separately in enums/Action
     *  @private
     */
    static get Action():any {
        return Action;
    }

    /**
     *  Documented separately in enums/Possession
     *  @private
     */
    static get Possession():any {
        return Possession;
    }

    /**
     *  Documented separately in AccessControlError
     *  @private
     */
    static get Error():any {
        return AccessControlError;
    }

    // -------------------------------
    //  PUBLIC STATIC METHODS
    // -------------------------------

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
    static filter(data:any, attributes:string[]):any {
        utils.filterAll(data, attributes);
    }

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
    static isACError(object:any):boolean {
        return object instanceof AccessControlError;
    }

    /**
     *  Alias of `isACError`
     *  @private
     */
    static isAccessControlError(object:any):boolean {
        return AccessControl.isACError(object);
    }
}

export { AccessControl };
