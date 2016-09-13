'use strict';Object.defineProperty(exports, "__esModule", { value: true });var _createClass = function () {function defineProperties(target, props) {for (var i = 0; i < props.length; i++) {var descriptor = props[i];descriptor.enumerable = descriptor.enumerable || false;descriptor.configurable = true;if ("value" in descriptor) descriptor.writable = true;Object.defineProperty(target, descriptor.key, descriptor);}}return function (Constructor, protoProps, staticProps) {if (protoProps) defineProperties(Constructor.prototype, protoProps);if (staticProps) defineProperties(Constructor, staticProps);return Constructor;};}();var _Factory = require('./Factory');var _Factory2 = _interopRequireDefault(_Factory);
var _helper = require('./lib/helper');var _helper2 = _interopRequireDefault(_helper);function _interopRequireDefault(obj) {return obj && obj.__esModule ? obj : { default: obj };}function _classCallCheck(instance, Constructor) {if (!(instance instanceof Constructor)) {throw new TypeError("Cannot call a class as a function");}}

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
                                                                                                                                                                                                                                                                                                                                         */var
AccessControl = function () {

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
    function AccessControl() {var grants = arguments.length <= 0 || arguments[0] === undefined ? {} : arguments[0];_classCallCheck(this, AccessControl);
        this.setGrants(grants);
        // initiate our inner classes
        this._factory = new _Factory2.default(this);
    }

    // -------------------------------
    //  PUBLIC METHODS
    // -------------------------------

    /**
     *  Gets the internal grants object that stores all current grants.
     *
     *  @return {Object} - Hash-map of grants.
     */_createClass(AccessControl, [{ key: 'getGrants', value: function getGrants()
        {
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
           */ }, { key: 'setGrants', value: function setGrants(
        grantsObject) {var _this = this;
            this._grants = {};
            var type = _helper2.default.type(grantsObject);
            if (type === 'object') {
                this._grants = grantsObject;
            } else if (type === 'array') {
                grantsObject.forEach(function (item) {return _this._grantAccess(item);});
            }
            return this;
        }

        /**
           *  Resets the internal grants object and removes all previous grants.
           *  @chainable
           *
           *  @returns {AccessControl} - `AccessControl` instance for chaining.
           */ }, { key: 'reset', value: function reset()
        {
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
           *  @throws {Error} - If a role tries to extend itself.
           */ }, { key: 'extendRole', value: function extendRole(
        roles, extenderRoles) {var _this2 = this;
            extenderRoles = _helper2.default.asArray(extenderRoles);
            _helper2.default.asArray(roles).forEach(function (role) {
                if (extenderRoles.indexOf(role) >= 0) {
                    throw new Error('AccessControl: Attempted to extend role "' + role + '" by itself.');
                }
                if (!_this2._grants.hasOwnProperty(role)) {
                    _this2._grants[role] = {
                        $extend: extenderRoles.concat() };

                } else {
                    var r = _this2._grants[role];
                    if (Array.isArray(r.$extend)) {
                        r.$extend = _helper2.default.uniqConcat(r.$extend, extenderRoles);
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
           */ }, { key: 'removeRoles', value: function removeRoles(
        roles) {var _this3 = this;
            var rolesToRemove = _helper2.default.asArray(roles);
            rolesToRemove.forEach(function (role) {
                delete _this3._grants[role];
            });
            // also remove these roles from $extend list of each remaining role.
            this._each(function (role, roleItem) {
                if (Array.isArray(roleItem.$extend)) {
                    roleItem.$extend = _helper2.default.subtractArray(roleItem.$extend, rolesToRemove);
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
           */ }, { key: 'removeResources', value: function removeResources(
        resources, roles) {
            // _removePermission has a third argument `actionPossession`. if
            // omitted (like below), removes the parent resource object.
            this._removePermission(resources, roles);
            return this;
        }

        /**
           *  Gets all the unique roles that have at least one grant.
           *
           *  @returns {Array}
           */ }, { key: 'getRoles', value: function getRoles()
        {
            return Object.keys(this._grants);
        }

        /**
           *  Gets all the unique resources that are granted access for at
           *  least one role.
           *
           *  @returns {Array}
           */ }, { key: 'getResources', value: function getResources()
        {
            // using an object for unique count
            var resources = {};
            this._eachRoleResource(function (role, resource, permissions) {
                resources[resource] = null;
            });
            return Object.keys(resources);
        }

        /**
           *  Checks whether any permissions are granted to the given role.
           *
           *  @returns {Boolean}
           */ }, { key: 'hasRole', value: function hasRole(
        role) {
            return this._grants.hasOwnProperty(role);
        }

        /**
           *  Checks whether any permissions are granted for the given resource.
           *
           *  @returns {Boolean}
           */ }, { key: 'hasResource', value: function hasResource(
        resource) {
            if (typeof resource !== 'string' || resource === '') {
                return false;
            }
            var resources = this.getResources();
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
           */ }, { key: 'filter', value: function filter(
        data, attributes) {
            _helper2.default.filterAll(data, attributes);
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
           */ }, { key: 'can', value: function can(
        rolesOrAccess) {
            return new this._factory.Access(rolesOrAccess);
        }

        /**
           *  Alias of `can()`.
           *  @private
           */ }, { key: 'access', value: function access(
        rolesOrAccess) {
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
           */ }, { key: 'permission', value: function permission(
        rolesOrPerm) {
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
           */ }, { key: 'grant', value: function grant(
        rolesOrGrant) {
            return new this._factory.Grant(rolesOrGrant);
        }

        /**
           *  Alias of `grant()`.
           *  @private
           */ }, { key: 'allow', value: function allow(
        rolesOrGrant) {
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
           */ }, { key: 'deny', value: function deny(
        rolesOrDeny) {
            return new this._factory.Deny(rolesOrDeny);
        }

        /**
           *  Alias of `deny()`.
           *  @private
           */ }, { key: 'reject', value: function reject(
        rolesOrDeny) {
            return this.deny(rolesOrDeny);
        }

        // -------------------------------
        //  PRIVATE METHODS
        // -------------------------------

        /**
         *  @private
         */ }, { key: '_each', value: function _each(
        callback) {var _this4 = this;
            _helper2.default.eachKey(this._grants, function (role) {return callback(role, _this4._grants[role]);});
        }

        /**
           *  @private
           */ }, { key: '_eachRole', value: function _eachRole(
        callback) {
            _helper2.default.eachKey(this._grants, function (role) {return callback(role);});
        }

        /**
           *  @private
           */ }, { key: '_eachRoleResource', value: function _eachRoleResource(
        callback) {var _this5 = this;
            var resources = void 0,permissions = void 0;
            this._eachRole(function (role) {
                resources = _this5._grants[role];
                _helper2.default.eachKey(resources, function (resource) {
                    permissions = role[resource];
                    callback(role, resource, permissions);
                });
            });
        }

        // CAUTION: if attributes is omitted, it will default to `['*']` which
        // means "all attributes allowed".
    }, { key: '_grantAccess', value: function _grantAccess(grant) {var _this6 = this;
            grant = _helper2.default.normalizeAccessObject(grant);
            // console.log(grant);
            var grantItem = void 0,resource = void 0,re = void 0,ap = void 0;
            // grant.role also accepts an array, so treat it like it.
            grant.role.forEach(function (role) {
                if (!_this6._grants.hasOwnProperty(role)) {
                    _this6._grants[role] = {};
                }
                grantItem = _this6._grants[role];
                re = grant.resource;
                if (!grantItem.hasOwnProperty(re)) {
                    grantItem[re] = {};
                }
                resource = grantItem[re];
                // If possession (in action value or as a separate property) is
                // omitted, it will default to "any". e.g. "create" —>
                // "create:any"
                ap = grant.action + ':' + grant.possession;
                resource[ap] = _helper2.default.asArray(grant.attributes, ',') || ['*']; // all attributes allowed
            });
        }

        /**
           *  @private
           */ }, { key: '_removePermission', value: function _removePermission(
        resources, roles, actionPossession) {var _this7 = this;
            resources = _helper2.default.asArray(resources);
            if (roles) roles = _helper2.default.asArray(roles);
            this._eachRoleResource(function (role, resource, permissions) {
                if (resources.indexOf(resource) >= 0
                // roles is optional. so remove if role is not defined.
                // if defined, check if the current role is in the list.
                && (!roles || roles.indexOf(role) >= 0)) {
                    if (actionPossession) {
                        delete _this7._grants[role][resource][actionPossession];
                    } else {
                        // this is used for AccessControl#removeResources().
                        delete _this7._grants[role][resource];
                    }
                }
            });
        }

        /**
           *  Removes the permission ("action:possession" property which represents
           *  the permission) from the corresponding resource object (in grants).
           *  @private
           */ }, { key: '_denyAccess', value: function _denyAccess(
        deny) {
            deny = _helper2.default.normalizeAccessObject(deny);
            var ap = deny.action + ':' + deny.possession;
            this._removePermission(deny.resource, deny.role, ap);
        } }]);return AccessControl;}();


// -------------------------------
//  EXPORT
// -------------------------------
exports.default =
AccessControl;
