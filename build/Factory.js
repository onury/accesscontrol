'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }(); // dep modules

// own modules


var _notation = require('notation');

var _notation2 = _interopRequireDefault(_notation);

var _enums = require('./enums');

var _enums2 = _interopRequireDefault(_enums);

var _helper = require('./lib/helper');

var _helper2 = _interopRequireDefault(_helper);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

exports.default = function (ac) {

    // -------------------------------
    //  CLASS: Permission
    // -------------------------------

    // below are equivalent
    // var permission = AccessControl.access(role).createAny(resource);
    // var permission = AccessControl.access(role).resource(resource).createAny();
    // var permission = AccessControl.access().role(role).resource(resource).createAny();
    // var permission = new AccessControl.Permission(role, action, possession, resource);

    // AccessControl.access('ADMIN').createAny('PROFILE').granted; // Boolean
    // AccessControl.access('ADMIN').createAny('PROFILE').attributes; // Array

    // var can = AccessControl.access;
    // var permission = can('USER').createOwn('PROFILE');
    // permission.granted // boolean
    // permission.attributes // Array

    // See AccessControl#permission
    var Permission = function () {
        function Permission(perm) {
            _classCallCheck(this, Permission);

            this._attributes = this._getUnionAttrsOfRoles(perm);
        }

        _createClass(Permission, [{
            key: 'filter',


            // equivalent to AccessControl.filter(data, attributes);
            value: function filter(data) {
                return _helper2.default.filterAll(data, this.attributes);
            }

            /**
             *  Gets roles and extended roles in a flat array.
             *  @private
             */

        }, {
            key: '_getFlatRoles',
            value: function _getFlatRoles(roles) {
                roles = _helper2.default.asArray(roles);
                var arr = roles.concat();
                roles.forEach(function (roleName) {
                    var role = ac._grants[roleName];
                    if (Array.isArray(role.$extend)) {
                        arr = _helper2.default.uniqConcat(arr, role.$extend);
                    }
                });
                return arr;
            }

            /**
             *  When more than one role is passed, we union the permitted attributes
             *  for all given roles; so we can check whether "at least one of these
             *  roles" have the permission to execute this action.
             *  e.g. `can(['admin', 'user']).createAny('video')`
             *  @private
             */

        }, {
            key: '_getUnionAttrsOfRoles',
            value: function _getUnionAttrsOfRoles(access) {
                if (!ac._grants) {
                    throw new Error('AccessControl: Grants are not set.');
                }
                // throws if has any invalid property value
                access = _helper2.default.normalizeAccessObject(access);

                var grantItem = void 0,
                    _resource = void 0,
                    attrsList = [],

                // get roles and extended roles in a flat array
                roles = this._getFlatRoles(access.role);
                // iterate through roles and add permission attributes (array) of
                // each role to attrsList (array).
                roles.forEach(function (role, index) {
                    grantItem = ac._grants[role];
                    if (grantItem) {
                        _resource = grantItem[access.resource];
                        if (_resource) {
                            // e.g. _resource['create:own']
                            // If action has possession "any", it will also return
                            // `granted=true` for "own", if "own" is not defined.
                            attrsList.push(_resource[access.action + ':' + access.possession] || _resource[access.action + ':any'] || []);
                            // console.log(_resource, 'for:', action + '.' + possession);
                        }
                    }
                });

                // union all arrays of (permitted resource) attributes (for each role)
                // into a single array.
                var attrs = [],
                    len = attrsList.length;
                if (len > 0) {
                    attrs = attrsList[0];
                    var i = 1;
                    while (i < len) {
                        attrs = _notation2.default.Glob.union(attrs, attrsList[i]);
                        i++;
                    }
                }
                return attrs;
            }
        }, {
            key: 'attributes',
            get: function get() {
                return this._attributes;
            }
        }, {
            key: 'granted',
            get: function get() {
                // check for a non-negated attribute
                return this.attributes.some(function (attr) {
                    return attr.slice(0, 1) !== '!';
                });
            }
        }]);

        return Permission;
    }();

    // -------------------------------
    //  CLASS: Access
    // -------------------------------

    // See AccessControl#can


    var Access = function () {
        function Access(rolesOrAccess) {
            _classCallCheck(this, Access);

            // if this is a (permission) object, we directly build attributes from
            // grants.
            if (_helper2.default.type(rolesOrAccess) === 'object') {
                this._access = rolesOrAccess;
            } else {
                // if this is just role(s); a string or array; we start building
                // the grant object for this.
                this._access = {
                    role: rolesOrAccess
                };
            }
        }

        _createClass(Access, [{
            key: 'role',
            value: function role(roles) {
                this._access.role = roles;
                return this;
            }
        }, {
            key: 'resource',
            value: function resource(_resource2) {
                this._access.resource = _resource2;
                return this;
            }
        }]);

        return Access;
    }();

    // -------------------------------
    //  CLASS: Grant
    // -------------------------------

    // See AccessControl#grant


    var Grant = function () {

        // If a grant object is passed, possession and attributes properties are
        // optional. CAUTION: if attributes is omitted, it will default to `['*']`
        // which means "all attributes allowed". If possession is omitted, it will
        // default to "any".
        function Grant(rolesOrGrant) {
            _classCallCheck(this, Grant);

            // if this is a (access grant) object, we directly add it to grants
            if (_helper2.default.type(rolesOrGrant) === 'object') {
                this._grant = rolesOrGrant;
                // Execute immediately if action is set. Otherwise,
                // action/possession will be set by action methods such as
                // `.createAny()`, `.readOwn()`, etc...
                if (_helper2.default.hasDefined(this._grant, 'action')) {
                    ac._grantAccess(this._grant);
                }
            } else {
                // if this is just role(s); a string or array; we start building
                // the grant object for this.
                this._grant = {
                    role: rolesOrGrant
                };
            }
        }

        _createClass(Grant, [{
            key: 'role',
            value: function role(roles) {
                this._grant.role = roles;
                return this;
            }
        }, {
            key: 'resource',
            value: function resource(_resource3) {
                this._grant.resource = _resource3;
                return this;
            }
        }, {
            key: 'attributes',
            value: function attributes(_attributes) {
                this._grant.attributes = _attributes;
                return this;
            }
        }, {
            key: 'extend',
            value: function extend(roles) {
                ac.extendRole(this._grant.role, roles);
                return this;
            }

            /**
             *  Shorthand to switch to a new `Grant` instance with a different role
             *  within the method chain.
             *  @example
             *  ac.grant('user').createOwn('video')
             *    .grant('admin').updateAny('video');
             */

        }, {
            key: 'grant',
            value: function grant(rolesOrGrant) {
                if (!rolesOrGrant) rolesOrGrant = this._grant.role;
                return new Grant(rolesOrGrant);
            }

            /**
             *  Shorthand to switch to a new `Deny` instance with a different
             *  (or same) role within the method chain.
             *  @example
             *  ac.grant('user').createOwn('video')
             *    .grant('admin').updateAny('video');
             */

        }, {
            key: 'deny',
            value: function deny(rolesOrDeny) {
                if (!rolesOrDeny) rolesOrDeny = this._grant.role;
                return new Deny(rolesOrDeny); // eslint-disable-line
            }
        }]);

        return Grant;
    }();

    // -------------------------------
    //  CLASS: Deny
    // -------------------------------

    // See AccessControl#deny


    var Deny = function () {

        // See AccessControl.Deny
        function Deny(rolesOrDeny) {
            _classCallCheck(this, Deny);

            // if this is a (access grant) object, we directly add it to grants
            if (_helper2.default.type(rolesOrDeny) === 'object') {
                this._deny = rolesOrDeny;
                if (_helper2.default.hasDefined(this._deny, 'action')) {
                    ac._denyAccess(this._deny);
                }
            } else {
                // if this is just role(s); a string or array; we start building
                // the grant object for this.
                this._deny = {
                    role: rolesOrDeny
                };
            }
        }

        _createClass(Deny, [{
            key: 'role',
            value: function role(roles) {
                this._deny.role = roles;
                return this;
            }
        }, {
            key: 'resource',
            value: function resource(_resource4) {
                this._deny.resource = _resource4;
                return this;
            }

            /**
             *  Shorthand to switch to a new `Deny` instance with a different role
             *  within the method chain.
             *  @example
             *  ac.grant('user').createOwn('video')
             *    .grant('admin').updateAny('video');
             */

        }, {
            key: 'deny',
            value: function deny(rolesOrDeny) {
                if (!rolesOrDeny) rolesOrDeny = this._deny.role;
                return new Deny(rolesOrDeny);
            }

            /**
             *  Shorthand to switch to a new `Grant` instance with a different
             *  (or same) role within the method chain.
             *  @example
             *  ac.grant('user').createOwn('video')
             *    .grant('admin').updateAny('video');
             */

        }, {
            key: 'grant',
            value: function grant(rolesOrGrant) {
                if (!rolesOrGrant) rolesOrGrant = this._deny.role;
                return new Grant(rolesOrGrant);
            }
        }]);

        return Deny;
    }();

    // -------------------------------
    //  INSTANCE (PROTOTYPE) METHODS
    // -------------------------------

    // Creating action (Prototype) Methods for
    // `Access`, `Grant` and `Deny` classes such as:
    // ---------------------------------------------
    // .createAny() .readAny() .updateAny() .deleteAny()
    // .createOwn() .readOwn() .updateOwn() .deleteOwn()
    // ---------------------------------------------
    // Also assigning aliases to <action>Any() methods:
    // .create() .read() .update() .delete()

    var method = void 0;
    _enums2.default.actions.forEach(function (action) {
        // create|read|update|delete
        _enums2.default.possessions.forEach(function (possession) {
            // any|own
            method = _helper2.default.getMethodName(action, possession);
            // Access.prototype.<action+Possession>
            // e.g. Access.prototype.createAny
            /**
             *  Action methods of `Access` prototype return a `Permission`
             *  object that defines the granted permission (attributes).
             *  These methods end the chain and throws if any invalid values
             *  are passed previously (via the rest of the chain-methods).
             */
            Access.prototype[method] = function (resource) {
                this._access.action = action;
                this._access.possession = possession;
                this._access.resource = resource || this._access.resource;
                return new Permission(this._access);
            };
            // assign aliases: Access.prototype.create = Access.prototype.createAny
            if (possession === 'any') {
                Access.prototype[action] = Access.prototype[method];
            }
            // Grant.prototype.<action+Possession>
            // e.g. Grant.prototype.createAny
            /**
             *  Action methods of `Grant` prototype add (grant) permission(s)
             *  for the defined role(s) and resource. These methods end the
             *  chain and throws if any invalid values are passed previously
             *  (via the rest of the chain-methods).
             */
            Grant.prototype[method] = function (resource, attributes) {
                this._grant.action = action;
                this._grant.possession = possession;
                this._grant.resource = resource || this._grant.resource;
                this._grant.attributes = attributes || this._grant.attributes;
                ac._grantAccess(this._grant);
                // important: reset attributes for chained methods
                this._grant.attributes = undefined;
                return this;
            };
            // assign aliases: Grant.prototype.create = Grant.prototype.createAny
            if (possession === 'any') {
                Grant.prototype[action] = Grant.prototype[method];
            }
            // Deny.prototype.<action+Possession>
            // e.g. Deny.prototype.createAny
            /**
             *  Action methods of `Deny` prototype remove (deny) permission(s)
             *  for the defined role(s) and resource. These methods end the
             *  chain and throws if any invalid values are passed previously
             *  (via the rest of the chain-methods).
             */
            Deny.prototype[method] = function (resource) {
                this._deny.action = action;
                this._deny.possession = possession;
                this._deny.resource = resource || this._deny.resource;
                ac._denyAccess(this._deny);
                return this;
            };
            // assign aliases: Deny.prototype.create = Deny.prototype.createAny
            if (possession === 'any') {
                Deny.prototype[action] = Deny.prototype[method];
            }
        });
    });

    // -------------------------------
    //  EXPORT
    // -------------------------------

    return {
        Permission: Permission,
        Access: Access,
        Grant: Grant,
        Deny: Deny
    };
};
