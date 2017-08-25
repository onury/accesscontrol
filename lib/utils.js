"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// dep modules
var Notation = require("notation");
// own modules
var enums_1 = require("./enums");
var core_1 = require("./core");
var utils = {
    type: function (o) {
        return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
    },
    hasDefined: function (o, propName) {
        return o.hasOwnProperty(propName) && o[propName] !== undefined;
    },
    toStringArray: function (value) {
        if (Array.isArray(value))
            return value;
        if (typeof value === 'string')
            return value.trim().split(/\s*[;,]\s*/);
        throw new core_1.AccessControlError('Cannot convert value to array!');
    },
    isFilledStringArray: function (arr) {
        for (var _i = 0, arr_1 = arr; _i < arr_1.length; _i++) {
            var s = arr_1[_i];
            if (typeof s !== 'string' || s.trim() === '')
                return false;
        }
        return true;
    },
    isStringOrArray: function (value) {
        return typeof value === 'string' || utils.isFilledStringArray(value);
    },
    isEmptyArray: function (value) {
        return Array.isArray(value) && value.length === 0;
    },
    uniqConcat: function (arrA, arrB) {
        var arr = arrA.concat();
        arrB.forEach(function (b) {
            if (arr.indexOf(b) < 0)
                arr.push(b);
        });
        return arr;
    },
    subtractArray: function (arrA, arrB) {
        return arrA.concat().filter(function (a) { return arrB.indexOf(a) === -1; });
    },
    eachKey: function (o, callback) {
        return Object.keys(o).forEach(callback);
    },
    /**
     *  Gets roles and extended roles in a flat array.
     */
    getFlatRoles: function (grants, roles) {
        roles = utils.toStringArray(roles);
        var arr = roles.concat();
        roles.forEach(function (roleName) {
            var role = grants[roleName];
            if (!role)
                throw new core_1.AccessControlError("Role not found: \"" + roleName + "\"");
            if (Array.isArray(role.$extend)) {
                arr = utils.uniqConcat(arr, role.$extend);
            }
        });
        return arr;
    },
    normalizeActionPossession: function (info) {
        // validate and normalize action
        if (typeof info.action !== 'string') {
            throw new core_1.AccessControlError("Invalid action: " + info.action);
        }
        var s = info.action.split(':');
        if (enums_1.actions.indexOf(s[0].trim().toLowerCase()) < 0) {
            throw new core_1.AccessControlError("Invalid action: " + s[0]);
        }
        info.action = s[0].trim().toLowerCase();
        // validate and normalize possession
        var poss = info.possession || s[1];
        if (poss) {
            if (enums_1.possessions.indexOf(poss.trim().toLowerCase()) < 0) {
                throw new core_1.AccessControlError("Invalid action possession: " + poss);
            }
            else {
                info.possession = poss.trim().toLowerCase();
            }
        }
        else {
            // if no possession is set, we'll default to "any".
            info.possession = enums_1.Possession.ANY;
        }
        return info;
    },
    normalizeQueryInfo: function (query, all) {
        if (all === void 0) { all = false; }
        // clone the object
        query = Object.assign({}, query);
        // validate and normalize role(s)
        query.role = utils.toStringArray(query.role);
        if (!utils.isFilledStringArray(query.role)) {
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(query.role));
        }
        // validate resource
        if (typeof query.resource !== 'string' || query.resource.trim() === '') {
            throw new core_1.AccessControlError("Invalid resource: \"" + query.resource + "\"");
        }
        query.resource = query.resource.trim();
        // this part is not necessary if this is invoked from a comitter method
        // such as `createAny()`. So we'll check if we need to validate all
        // properties such as `action` and `possession`.
        if (all)
            query = utils.normalizeActionPossession(query);
        return query;
    },
    normalizeAccessInfo: function (access, all) {
        if (all === void 0) { all = false; }
        // clone the object
        access = Object.assign({}, access);
        // validate and normalize role(s)
        access.role = utils.toStringArray(access.role);
        if (!utils.isFilledStringArray(access.role)) {
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(access.role));
        }
        // validate and normalize resource
        access.resource = utils.toStringArray(access.resource);
        if (!utils.isFilledStringArray(access.resource)) {
            throw new core_1.AccessControlError("Invalid resource(s): " + JSON.stringify(access.resource));
        }
        // normalize attributes
        if (access.denied || (Array.isArray(access.attributes) && access.attributes.length === 0)) {
            access.attributes = [];
        }
        else {
            // if omitted and not denied, all attributes are allowed
            access.attributes = !access.attributes ? ['*'] : utils.toStringArray(access.attributes);
        }
        // this part is not necessary if this is invoked from a comitter method
        // such as `createAny()`. So we'll check if we need to validate all
        // properties such as `action` and `possession`.
        if (all)
            access = utils.normalizeActionPossession(access);
        return access;
    },
    /**
     *  Used to re-set (prepare) the `attributes` of an `IAccessInfo` object
     *  when it's first initialized with e.g. `.grant()` or `.deny()` chain
     *  methods.
     *  @param {IAccessInfo} access
     *  @returns {IAccessInfo}
     */
    resetAttributes: function (access) {
        if (access.denied) {
            access.attributes = [];
            return access;
        }
        if (!access.attributes || utils.isEmptyArray(access.attributes)) {
            access.attributes = ['*'];
        }
        return access;
    },
    /**
     *  Checks whether the given access info can be commited to grants model.
     *  @param {IAccessInfo|IQueryInfo} info
     *  @returns {Boolean}
     */
    isInfoFulfilled: function (info) {
        return utils.hasDefined(info, 'role')
            && utils.hasDefined(info, 'action')
            && utils.hasDefined(info, 'resource');
    },
    /**
     *  Commits the given `IAccessInfo` object to the grants model.
     *  CAUTION: if attributes is omitted, it will default to `['*']` which
     *  means "all attributes allowed".
     *  @param {Any} grants
     *  @param {IAccessInfo} access
     *  @param {Boolean} normalizeAll
     *         Specifies whether to validate and normalize all properties of
     *         the inner `IAccessInfo` object, including `action` and `possession`.
     *  @throws {Error} If `IAccessInfo` object fails validation.
     */
    commitToGrants: function (grants, access, normalizeAll) {
        if (normalizeAll === void 0) { normalizeAll = false; }
        access = utils.normalizeAccessInfo(access, normalizeAll);
        // console.log(access);
        // grant.role also accepts an array, so treat it like it.
        access.role.forEach(function (role) {
            if (!grants.hasOwnProperty(role))
                grants[role] = {};
            var grantItem = grants[role];
            var ap = access.action + ':' + access.possession;
            access.resource.forEach(function (res) {
                if (!grantItem.hasOwnProperty(res))
                    grantItem[res] = {};
                // If possession (in action value or as a separate property) is
                // omitted, it will default to "any". e.g. "create" —>
                // "create:any"
                grantItem[res][ap] = access.attributes;
            });
        });
    },
    /**
     *  When more than one role is passed, we union the permitted attributes
     *  for all given roles; so we can check whether "at least one of these
     *  roles" have the permission to execute this action.
     *  e.g. `can(['admin', 'user']).createAny('video')`
     *
     *  @param {Any} grants
     *  @param {IQueryInfo} query
     *
     *  @returns {Array<String>} - Array of union'ed attributes.
     */
    getUnionAttrsOfRoles: function (grants, query) {
        if (!grants) {
            throw new core_1.AccessControlError('Grants are not set.');
        }
        // throws if has any invalid property value
        query = utils.normalizeQueryInfo(query);
        var grantItem;
        var resource;
        var attrsList = [];
        // get roles and extended roles in a flat array
        var roles = utils.getFlatRoles(grants, query.role);
        // iterate through roles and add permission attributes (array) of
        // each role to attrsList (array).
        roles.forEach(function (role, index) {
            grantItem = grants[role];
            if (grantItem) {
                resource = grantItem[query.resource];
                if (resource) {
                    // e.g. resource['create:own']
                    // If action has possession "any", it will also return
                    // `granted=true` for "own", if "own" is not defined.
                    attrsList.push((resource[query.action + ':' + query.possession]
                        || resource[query.action + ':any']
                        || []).concat());
                    // console.log(resource, 'for:', action + '.' + possession);
                }
            }
        });
        // union all arrays of (permitted resource) attributes (for each role)
        // into a single array.
        var attrs = [];
        var len = attrsList.length;
        if (len > 0) {
            attrs = attrsList[0];
            var i = 1;
            while (i < len) {
                attrs = Notation.Glob.union(attrs, attrsList[i]);
                i++;
            }
        }
        return attrs;
    },
    /**
     *  Checks the given grants model and gets an array of non-existent roles
     *  from the given roles.
     *  @param {Any} grants - Grants model to be checked.
     *  @param {Array<string>} roles - Roles to be checked.
     *  @returns {Array<String>} - Array of non-existent roles. Empty array if
     *  all exist.
     */
    getNonExistentRoles: function (grants, roles) {
        var non = [];
        for (var _i = 0, roles_1 = roles; _i < roles_1.length; _i++) {
            var role = roles_1[_i];
            if (!grants.hasOwnProperty(role))
                non.push(role);
        }
        return non;
    },
    /**
     *  Extends the given role(s) with privileges of one or more other roles.
     *
     *  @param {Any} grants
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
     *  @throws {Error}
     *          If a role is extended by itself or a non-existent role.
     */
    extendRole: function (grants, roles, extenderRoles) {
        var arrExtRoles = utils.toStringArray(extenderRoles);
        var nonExistentExtRoles = utils.getNonExistentRoles(grants, arrExtRoles);
        if (nonExistentExtRoles.length > 0) {
            throw new core_1.AccessControlError("Cannot extend with non-existent role(s): \"" + nonExistentExtRoles.join(', ') + "\"");
        }
        utils.toStringArray(roles).forEach(function (role) {
            if (arrExtRoles.indexOf(role) >= 0) {
                throw new core_1.AccessControlError("Attempted to extend role \"" + role + "\" by itself.");
            }
            if (!grants.hasOwnProperty(role)) {
                grants[role] = {
                    $extend: arrExtRoles.concat()
                };
            }
            else {
                var r = grants[role];
                if (Array.isArray(r.$extend)) {
                    r.$extend = utils.uniqConcat(r.$extend, arrExtRoles);
                }
                else {
                    r.$extend = arrExtRoles.concat();
                }
            }
        });
    },
    filter: function (object, attributes) {
        if (!Array.isArray(attributes) || attributes.length === 0) {
            return {};
        }
        var notation = new Notation(object);
        return notation.filter(attributes).value;
    },
    filterAll: function (arrOrObj, attributes) {
        if (!Array.isArray(arrOrObj)) {
            return utils.filter(arrOrObj, attributes);
        }
        return arrOrObj.map(function (o) {
            return utils.filter(o, attributes);
        });
    }
};
exports.default = utils;
