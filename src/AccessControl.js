import Factory from './Factory';
import helper from './lib/helper';

/**
 *  AccessControl class that implements RBAC (Role-Based Access Control) basics
 *  and ABAC (Attribute-Based Access Control) <i>resource</i> and <i>action</i>
 *  attributes.
 *  @author   Onur Yıldırım (onur@cutepilot.com)
 *  @license  MIT
 *
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
 *  var permission = ac.can('admin').readAny('profile');
 *  permission.granted // true
 *  permission.attributes // ["*", "!password"]
 *  permission.filter(data) // { uid, email, address, account }
 *
 *  ac.deny('admin').createAny('profile');
 *  ac.can('admin').createAny('profile').granted // false
 *
 *  // To add a grant but deny access
 *  ac.grant('admin').createAny('profile', []); // no attributes allowed
 *  ac.can('admin').createAny('profile').granted // false
 *
 *  console.log(ac.getGrants());
 *  // outputs:
 *  {
 *      admin: {
 *          profile: {
 *              "read:any": ["*", "!password"],
 *              "update:any": ["*"],
 *              "delete:any": ["*"]
 *          },
 *          video: {
 *              "read:any": ["*"],
 *              "update:any": ["*", "!userId"],
 *              "delete:any": ["*"]
 *          }
 *      },
 *      user: {
 *          profile: {
 *              "read:own": ["uid", "email", "address.*", "!account.roles"],
 *              "update:own": ["uid", "email", "password", "address.*", "!account.roles"],
 *              "delete:own": ["*"]
 *          },
 *          video: {
 *              "create:own": ["*", "!geo.*"],
 *              "read:any": ["*"],
 *              "update:own": ["*", "!geo.*"],
 *              "delete:own": ["*"],
 *          }
 *      }
 *  }
 */
class AccessControl {

    /**
     *  Initializes a new instance of `AccessControl` with the given grants.
     *
     *  @param {Object|Array} grants - A list containing the access grant
     *      definitions. See the structure of this object in the examples.
     *
     *  @example
     *  var grants = {
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
     *  var ac = new AccessControl(grants);
     *
     *  // The passed object can also be an array, such as a flat list
     *  // fetched from a database.
     *
     *  var flatList = [
     *      { role: "role1", resource: "resource1", action: "create:any", attributes: [ attrs ] },
     *      { role: "role1", resource: "resource1", action: "read:own", attributes: [ attrs ] },
     *      { role: "role2", ... },
     *      ...
     *  ];
     *
     *  // We turn this list into a hashtable for better performance. We aggregate
     *  // the list by roles first, resources second. If possession (in action
     *  // value or as a separate property) is omitted, it will default to "any".
     *  // e.g. "create" —> "create:any"
     *
     *  // Below are equivalent:
     *  { role: "role1", resource: "resource1", action: "create:any", attributes: [ attrs ] }
     *  { role: "role1", resource: "resource1", action: "create", possession: "any", attributes: [ attrs ] }
     *
     *  var ac = new AccessControl(flatList);
     *  console.log(ac.getGrants());
     *
     *  // This flat list is turned into:
     *  {
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
     *  }
     */
    constructor(grants = {}) {
        this.setGrants(grants);
        // initiate our inner classes
        this._factory = new Factory(this);
    }

    // -------------------------------
    //  PUBLIC METHODS
    // -------------------------------

    /**
     *  Gets the internal grants object that stores all current grants.
     *
     *  @return {Object} - Hash-map of grants.
     */
    getGrants() {
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
    setGrants(grantsObject) {
        this._grants = {};
        let type = helper.type(grantsObject);
        if (type === 'object') {
            this._grants = grantsObject;
        } else if (type === 'array') {
            grantsObject.forEach(item => this._grantAccess(item));
        }
        return this;
    }

    /**
     *  Resets the internal grants object and removes all previous grants.
     *  @chainable
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     */
    reset() {
        this._grants = {};
        return this;
    }

    /**
     *  Extends the given role(s) with privileges of one or more other roles.
     *  @chainable
     *
     *  @param {String|Array} roles
     *         Role(s) to be extended.
     *         Single role as a `String` or multiple roles as an `Array`.
     *
     *  @param {String|Array} extenderRoles
     *         Role(s) to inherit from.
     *         Single role as a `String` or multiple roles as an `Array`.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     *
     *  @throws {Error} - If a role is extended by itself.
     */
    extendRole(roles, extenderRoles) {
        extenderRoles = helper.asArray(extenderRoles);
        helper.asArray(roles).forEach(role => {
            if (extenderRoles.indexOf(role) >= 0) {
                throw new Error(`AccessControl: Attempted to extend role "${role}" by itself.`);
            }
            if (!this._grants.hasOwnProperty(role)) {
                this._grants[role] = {
                    $extend: extenderRoles.concat()
                };
            } else {
                let r = this._grants[role];
                if (Array.isArray(r.$extend)) {
                    r.$extend = helper.uniqConcat(r.$extend, extenderRoles);
                } else {
                    r.$extend = extenderRoles.concat();
                }
            }
        });
        return this;
    }

    /**
     *  Removes all the given role(s) and their granted permissions, at once.
     *  @chainable
     *
     *  @param {String|Array} roles - An array of roles to be removed.
     *      Also accepts a string that can be used to remove a single role.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     */
    removeRoles(roles) {
        let rolesToRemove = helper.asArray(roles);
        rolesToRemove.forEach(role => {
            delete this._grants[role];
        });
        // also remove these roles from $extend list of each remaining role.
        this._each((role, roleItem) => {
            if (Array.isArray(roleItem.$extend)) {
                roleItem.$extend = helper.subtractArray(roleItem.$extend, rolesToRemove);
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
     *  @param {String|Array} resources - A single or array of resources to
     *      be removed.
     *  @param {String|Array} [roles] - A single or array of roles to
     *      be removed. If omitted, permissions for all roles to all given
     *      resources will be removed.
     *
     *  @returns {AccessControl} - `AccessControl` instance for chaining.
     */
    removeResources(resources, roles) {
        // _removePermission has a third argument `actionPossession`. if
        // omitted (like below), removes the parent resource object.
        this._removePermission(resources, roles);
        return this;
    }

    /**
     *  Gets all the unique roles that have at least one grant.
     *
     *  @returns {Array}
     */
    getRoles() {
        return Object.keys(this._grants);
    }

    /**
     *  Gets all the unique resources that are granted access for at
     *  least one role.
     *
     *  @returns {Array}
     */
    getResources() {
        // using an object for unique count
        let resources = {};
        this._eachRoleResource((role, resource, permissions) => {
            resources[resource] = null;
        });
        return Object.keys(resources);
    }

    /**
     *  Checks whether any permissions are granted to the given role.
     *
     *  @returns {Boolean}
     */
    hasRole(role) {
        return this._grants.hasOwnProperty(role);
    }

    /**
     *  Checks whether any permissions are granted for the given resource.
     *
     *  @returns {Boolean}
     */
    hasResource(resource) {
        if (typeof resource !== 'string' || resource === '') {
            return false;
        }
        let resources = this.getResources();
        return resources.indexOf(resource) >= 0;
    }

    /**
     *  Deep clones the given data object(s) while filtering its properties
     *  by the given attribute (glob) notations. Includes all matched
     *  properties and removes the rest.
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
    filter(data, attributes) {
        helper.filterAll(data, attributes);
    }

    /**
     *  Gets an instance of `Access` (inner) object. This is used to check
     *  whether the defined access is allowed for the given role(s) and resource.
     *  This object provides chainable methods to build and define the access
     *  to be checked.
     *  @alias AccessControl#access
     *  @chainable
     *
     *  @param {String|Array|Object} rolesOrAccess - A single role (as a string),
     *      a list of roles (as an array) or an object that fully or partially
     *      defines the access to be checked.
     *
     *  @returns {AccessControl~Access} - The returned object provides chainable
     *      methods to build and define the access permissions to be checked.
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
    can(rolesOrAccess) {
        return new this._factory.Access(rolesOrAccess);
    }

    /**
     *  Alias of `can()`.
     *  @private
     */
    access(rolesOrAccess) {
        return this.can(rolesOrAccess);
    }

    /**
     *  Gets an instance of `Permission` (inner) object that checks and defines
     *  the granted access permissions for the target resource and role.
     *  Normally you would use `AccessControl#can()` method to check for
     *  permissions but this is useful if you need to check at once by passing
     *  a grant object; instead of chaining methods
     *  (as in `.can(role).action(resource)`).
     *
     *  Returned object has the following members:
     *
     *  @property {Boolean} granted
     *            Whether the specified resource permissions are granted for
     *            the given role.
     *  @property {Array} attributes
     *            The defined attributes for the specified resource and
     *            permissions. This will return an empty array if `granted` is
     *            `false`.
     *  @property {Function} filter
     *            Method that filters the properties of the given data object
     *            or array of objects, by granted permission attributes. Accepts
     *            a single argument; an object or array of objects to be
     *            filtered by the resulting attributes. This is equivalent to
     *            `AccessControl#filter(object, attributes)` method only with
     *            one difference that you don't need to pass the attributes
     *            argument.
     *
     *  @returns {AccessControl~Permission} - An object that provides properties
     *  and methods that defines the granted access permissions.
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
    permission(rolesOrPerm) {
        return new this._factory.Permission(rolesOrPerm);
    }

    /**
     *  Gets an instance of `Grant` (inner) object. This is used to grant access
     *  to specified resource(s) for the given role(s).
     *  @alias AccessControl#allow
     *  @chainable
     *
     *  @param {String|Array|Object} rolesOrGrant - A single role (as a string),
     *      a list of roles (as an array) or an object that fully or partially
     *      defines the access to be granted.
     *
     *  @return {AccessControl~Access} - The returned object provides chainable
     *      properties to build and define the access to be granted. See the
     *      examples for details.
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
    grant(rolesOrGrant) {
        return new this._factory.Grant(rolesOrGrant);
    }

    /**
     *  Alias of `grant()`.
     *  @private
     */
    allow(rolesOrGrant) {
        return this.grant(rolesOrGrant);
    }

    /**
     *  Gets an instance of `Deny` (inner) object. This is used to deny access
     *  to specified resource(s) for the given role(s). Denying will only remove
     *  a previously created grant. So if not granted before, you don't need
     *  to deny an access.
     *  @alias AccessControl#reject
     *  @chainable
     *
     *  @param {String|Array|Object} rolesOrGrant - A single role (as a string),
     *      a list of roles (as an array) or an object that fully or partially
     *      defines the access to be granted.
     *
     *  @return {AccessControl~Access} - The returned object provides chainable
     *      properties to build and define the access to be granted.
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
    deny(rolesOrDeny) {
        return new this._factory.Deny(rolesOrDeny);
    }

    /**
     *  Alias of `deny()`.
     *  @private
     */
    reject(rolesOrDeny) {
        return this.deny(rolesOrDeny);
    }

    // -------------------------------
    //  PRIVATE METHODS
    // -------------------------------

    /**
     *  @private
     */
    _each(callback) {
        helper.eachKey(this._grants, role => callback(role, this._grants[role]));
    }

    /**
     *  @private
     */
    _eachRole(callback) {
        helper.eachKey(this._grants, role => callback(role));
    }

    /**
     *  @private
     */
    _eachRoleResource(callback) {
        let resources, permissions;
        this._eachRole(role => {
            resources = this._grants[role];
            helper.eachKey(resources, resource => {
                permissions = role[resource];
                callback(role, resource, permissions);
            });
        });
    }

    // CAUTION: if attributes is omitted, it will default to `['*']` which
    // means "all attributes allowed".
    _grantAccess(grant) {
        grant = helper.normalizeAccessObject(grant);
        // console.log(grant);
        let grantItem, resource, re, ap;
        // grant.role also accepts an array, so treat it like it.
        grant.role.forEach(role => {
            if (!this._grants.hasOwnProperty(role)) {
                this._grants[role] = {};
            }
            grantItem = this._grants[role];
            re = grant.resource;
            if (!grantItem.hasOwnProperty(re)) {
                grantItem[re] = {};
            }
            resource = grantItem[re];
            // If possession (in action value or as a separate property) is
            // omitted, it will default to "any". e.g. "create" —>
            // "create:any"
            ap = grant.action + ':' + grant.possession;
            resource[ap] = helper.asArray(grant.attributes, ',') || ['*']; // all attributes allowed
        });
    }

    /**
     *  @private
     */
    _removePermission(resources, roles, actionPossession) {
        resources = helper.asArray(resources);
        if (roles) roles = helper.asArray(roles);
        this._eachRoleResource((role, resource, permissions) => {
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

    /**
     *  Removes the permission ("action:possession" property which represents
     *  the permission) from the corresponding resource object (in grants).
     *  @private
     */
    _denyAccess(deny) {
        deny = helper.normalizeAccessObject(deny);
        let ap = deny.action + ':' + deny.possession;
        this._removePermission(deny.resource, deny.role, ap);
    }
}

// -------------------------------
//  EXPORT
// -------------------------------

export default AccessControl;
