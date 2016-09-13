// dep modules
import Notation from 'notation';
// own modules
import enums from './enums';
import helper from './lib/helper';

export default (ac) => {

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
    class Permission {

        constructor(perm) {
            this._attributes = this._getUnionAttrsOfRoles(perm);
        }

        get attributes() {
            return this._attributes;
        }

        get granted() {
            // check for a non-negated attribute
            return this.attributes.some(attr => {
                return attr.slice(0, 1) !== '!';
            });
        }

        // equivalent to AccessControl.filter(data, attributes);
        filter(data) {
            return helper.filterAll(data, this.attributes);
        }

        /**
         *  Gets roles and extended roles in a flat array.
         *  @private
         */
        _getFlatRoles(roles) {
            roles = helper.asArray(roles);
            let arr = roles.concat();
            roles.forEach(roleName => {
                let role = ac._grants[roleName];
                if (Array.isArray(role.$extend)) {
                    arr = helper.uniqConcat(arr, role.$extend);
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
        _getUnionAttrsOfRoles(access) {
            if (!ac._grants) {
                throw new Error('AccessControl: Grants are not set.');
            }
            // throws if has any invalid property value
            access = helper.normalizeAccessObject(access);

            let grantItem, _resource,
                attrsList = [],
                // get roles and extended roles in a flat array
                roles = this._getFlatRoles(access.role);
            // iterate through roles and add permission attributes (array) of
            // each role to attrsList (array).
            roles.forEach((role, index) => {
                grantItem = ac._grants[role];
                if (grantItem) {
                    _resource = grantItem[access.resource];
                    if (_resource) {
                        // e.g. _resource['create:own']
                        // If action has possession "any", it will also return
                        // `granted=true` for "own", if "own" is not defined.
                        attrsList.push(
                            _resource[access.action + ':' + access.possession]
                                || _resource[access.action + ':any']
                                || []
                        );
                        // console.log(_resource, 'for:', action + '.' + possession);
                    }
                }
            });

            // union all arrays of (permitted resource) attributes (for each role)
            // into a single array.
            let attrs = [],
                len = attrsList.length;
            if (len > 0) {
                attrs = attrsList[0];
                let i = 1;
                while (i < len) {
                    attrs = Notation.Glob.union(attrs, attrsList[i]);
                    i++;
                }
            }
            return attrs;
        }
    }

    // -------------------------------
    //  CLASS: Access
    // -------------------------------

    // See AccessControl#can
    class Access {

        constructor(rolesOrAccess) {
            // if this is a (permission) object, we directly build attributes from
            // grants.
            if (helper.type(rolesOrAccess) === 'object') {
                this._access = rolesOrAccess;
            } else {
                // if this is just role(s); a string or array; we start building
                // the grant object for this.
                this._access = {
                    role: rolesOrAccess
                };
            }
        }

        role(roles) {
            this._access.role = roles;
            return this;
        }

        resource(resource) {
            this._access.resource = resource;
            return this;
        }
    }

    // -------------------------------
    //  CLASS: Grant
    // -------------------------------

    // See AccessControl#grant
    class Grant {

        // If a grant object is passed, possession and attributes properties are
        // optional. CAUTION: if attributes is omitted, it will default to `['*']`
        // which means "all attributes allowed". If possession is omitted, it will
        // default to "any".
        constructor(rolesOrGrant) {
            // if this is a (access grant) object, we directly add it to grants
            if (helper.type(rolesOrGrant) === 'object') {
                this._grant = rolesOrGrant;
                // Execute immediately if action is set. Otherwise,
                // action/possession will be set by action methods such as
                // `.createAny()`, `.readOwn()`, etc...
                if (helper.hasDefined(this._grant, 'action')) {
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

        role(roles) {
            this._grant.role = roles;
            return this;
        }

        resource(resource) {
            this._grant.resource = resource;
            return this;
        }

        attributes(attributes) {
            this._grant.attributes = attributes;
            return this;
        }

        extend(roles) {
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
        grant(rolesOrGrant) {
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
        deny(rolesOrDeny) {
            if (!rolesOrDeny) rolesOrDeny = this._grant.role;
            return new Deny(rolesOrDeny); // eslint-disable-line
        }
    }

    // -------------------------------
    //  CLASS: Deny
    // -------------------------------

    // See AccessControl#deny
    class Deny {

        // See AccessControl.Deny
        constructor(rolesOrDeny) {
            // if this is a (access grant) object, we directly add it to grants
            if (helper.type(rolesOrDeny) === 'object') {
                this._deny = rolesOrDeny;
                if (helper.hasDefined(this._deny, 'action')) {
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
        role(roles) {
            this._deny.role = roles;
            return this;
        }

        resource(resource) {
            this._deny.resource = resource;
            return this;
        }

        /**
         *  Shorthand to switch to a new `Deny` instance with a different role
         *  within the method chain.
         *  @example
         *  ac.grant('user').createOwn('video')
         *    .grant('admin').updateAny('video');
         */
        deny(rolesOrDeny) {
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
        grant(rolesOrGrant) {
            if (!rolesOrGrant) rolesOrGrant = this._deny.role;
            return new Grant(rolesOrGrant);
        }
    }

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

    let method;
    enums.actions.forEach(action => { // create|read|update|delete
        enums.possessions.forEach(possession => { // any|own
            method = helper.getMethodName(action, possession);
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
        Permission,
        Access,
        Grant,
        Deny
    };

};
