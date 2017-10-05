"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
// dep modules
var Notation = require("notation");
var enums_1 = require("./enums");
var core_1 = require("./core");
/**
 *  List of reserved keywords.
 *  i.e. Roles, resources with these names are not allowed.
 */
var RESERVED_KEYWORDS = ['$', '$extend'];
exports.RESERVED_KEYWORDS = RESERVED_KEYWORDS;
/**
 *  Error message to be thrown after AccessControl instance is locked.
 */
var ERR_LOCK = 'Cannot alter the underlying grants model. AccessControl instance is locked.';
exports.ERR_LOCK = ERR_LOCK;
var utils = {
    // ----------------------
    // GENERIC UTILS
    // ----------------------
    /**
     *  Gets the type of the given object.
     *  @param {Any} o
     *  @returns {String}
     */
    type: function (o) {
        return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
    },
    // for later use
    // isPlainObject(o:any) {
    //     return o && (o.constructor === Object || o.constructor === undefined);
    // },
    /**
     *  Specifies whether the given value is set (other that `null` or
     *  `undefined`).
     *  @param {Any} o - Value to be checked.
     *  @returns {Boolean}
     */
    // isset(o:any):boolean {
    //     return o === null || o === undefined;
    // },
    /**
     *  Specifies whether the property/key is defined on the given object.
     *  @param {Object} o
     *  @param {string} propName
     *  @returns {Boolean}
     */
    hasDefined: function (o, propName) {
        return o.hasOwnProperty(propName) && o[propName] !== undefined;
    },
    /**
     *  Converts the given (string) value into an array of string.
     *  Note that this does not throw if the value is not a string or array.
     *  It will silently return `null`.
     *  @param {Any} value
     *  @returns {Boolean|null}
     */
    toStringArray: function (value) {
        if (Array.isArray(value))
            return value;
        if (typeof value === 'string')
            return value.trim().split(/\s*[;,]\s*/);
        // throw new Error('Cannot convert value to array!');
        return null;
    },
    /**
     *  Checks whether the given array consists of non-empty string items.
     *  @param {Array} arr - Array to be checked.
     *  @returns {Boolean}
     */
    isFilledStringArray: function (arr) {
        if (!arr || !Array.isArray(arr))
            return false;
        for (var _i = 0, arr_1 = arr; _i < arr_1.length; _i++) {
            var s = arr_1[_i];
            if (typeof s !== 'string' || s.trim() === '')
                return false;
        }
        return true;
    },
    /**
     *  Checks whether the given value is a string or array.
     *  @param {Any} value - Value to be checked.
     *  @returns {Boolean}
     */
    isStringOrArray: function (value) {
        return typeof value === 'string' || utils.isFilledStringArray(value);
    },
    /**
     *  Checks whether the given value is an empty array.
     *  @param {Any} value - Value to be checked.
     *  @returns {Boolean}
     */
    isEmptyArray: function (value) {
        return Array.isArray(value) && value.length === 0;
    },
    /**
     *  Ensures that the pushed item is unique in the target array.
     *  @param {Array} arr - Target array.
     *  @param {Any} item - Item to be pushed to array.
     *  @returns {Array}
     */
    pushUniq: function (arr, item) {
        if (arr.indexOf(item) < 0)
            arr.push(item);
        return arr;
    },
    /**
     *  Concats the given two arrays and ensures all items are unique.
     *  @param {Array} arrA
     *  @param {Array} arrB
     *  @returns {Array} - Concat'ed array.
     */
    uniqConcat: function (arrA, arrB) {
        var arr = arrA.concat();
        arrB.forEach(function (b) {
            utils.pushUniq(arr, b);
        });
        return arr;
    },
    /**
     *  Subtracts the second array from the first.
     *  @param {Array} arrA
     *  @param {Array} arrB
     *  @return {Array} - Resulting array.
     */
    subtractArray: function (arrA, arrB) {
        return arrA.concat().filter(function (a) { return arrB.indexOf(a) === -1; });
    },
    /**
     *  Deep freezes the given object.
     *  @param {Object} o - Object to be frozen.
     *  @returns {Object} - Frozen object.
     */
    deepFreeze: function (o) {
        // Object.freeze accepts also an array. But here, we only use this for
        // objects.
        if (utils.type(o) !== 'object')
            return;
        var props = Object.getOwnPropertyNames(o);
        // freeze deeper before self
        props.forEach(function (key) {
            var sub = o[key];
            if (Array.isArray(sub))
                Object.freeze(sub);
            if (utils.type(sub) === 'object') {
                utils.deepFreeze(sub);
            }
        });
        // finally freeze self
        return Object.freeze(o);
    },
    /**
     *  Similar to JS .forEach, except this allows for breaking out early,
     *  (before all iterations are executed) by returning `false`.
     *  @param array
     *  @param callback
     *  @param thisArg
     */
    each: function (array, callback, thisArg) {
        if (thisArg === void 0) { thisArg = null; }
        var length = array.length;
        var index = -1;
        while (++index < length) {
            if (callback.call(thisArg, array[index], index, array) === false)
                break;
        }
    },
    /**
     *  Iterates through the keys of the given object. Breaking out early is
     *  possible by returning `false`.
     *  @param object
     *  @param callback
     */
    eachKey: function (object, callback) {
        // return Object.keys(o).forEach(callback);
        // forEach has no way to interrupt execution, short-circuit unless an
        // error is thrown. so we use this:
        utils.each(Object.keys(object), callback);
    },
    // ----------------------
    // AC VALIDATION UTILS
    // ----------------------
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
     *  Checks whether the given name can be used and is not a reserved keyword.
     *
     *  @param {String} name - Name to be checked.
     *  @param {Boolean} [throwOnInvalid=true] - Specifies whether to throw if
     *  name is not valid.
     *  @param {String} [msg] - Message to be thrown if `throwOnInvalid` is
     *  enabled and name is not valid.
     *
     *  @returns {Boolean}
     *
     *  @throws {AccessControlError} - If `throwOnInvalid` is enabled and name
     *  is invalid.
     */
    validName: function (name, throwOnInvalid, msg) {
        if (throwOnInvalid === void 0) { throwOnInvalid = true; }
        if (RESERVED_KEYWORDS.indexOf(name) >= 0) {
            if (!throwOnInvalid)
                return false;
            throw new core_1.AccessControlError(msg || "Cannot use reserved name: \"" + name + "\"");
        }
        return true;
    },
    /**
     *  Checks whether the given array does not contain a reserved keyword.
     *
     *  @param {String|Array<String>} list - Name(s) to be checked.
     *  @param {Boolean} [throwOnInvalid=true] - Specifies whether to throw if
     *  name is not valid.
     *  @param {String} [msg] - Message to be thrown if `throwOnInvalid` is
     *  enabled and name is not valid.
     *
     *  @returns {Boolean}
     *
     *  @throws {AccessControlError} - If `throwOnInvalid` is enabled and name
     *  is invalid.
     */
    hasValidNames: function (list, throwOnInvalid, msg) {
        if (throwOnInvalid === void 0) { throwOnInvalid = true; }
        var allValid = true;
        utils.each(utils.toStringArray(list), function (name) {
            if (!utils.validName(name, throwOnInvalid, msg)) {
                allValid = false;
                return false; // break out of loop
            }
            // suppress tslint warning
            return true; // continue
        });
        return allValid;
    },
    /**
     *  Checks whether the given object is a valid resource definition object.
     *
     *  @param {Object} o - Resource definition to be checked.
     *  @param {Boolean} [throwOnInvalid=true] - Specifies whether to throw if
     *  given object is not valid.
     *
     *  @returns {Boolean}
     *
     *  @throws {AccessControlError} - If `throwOnInvalid` is enabled and object
     *  is invalid.
     */
    validResourceObject: function (o, throwOnInvalid) {
        if (throwOnInvalid === void 0) { throwOnInvalid = true; }
        if (utils.type(o) !== 'object')
            return false;
        var valid = true;
        utils.eachKey(o, function (action) {
            var s = action.split(':');
            if (enums_1.actions.indexOf(s[0]) === -1) {
                if (throwOnInvalid)
                    throw new core_1.AccessControlError("Invalid action: \"" + action + "\"");
                valid = false;
                return false; // break out of loop
            }
            if (s[1] && enums_1.possessions.indexOf(s[1]) === -1) {
                if (throwOnInvalid)
                    throw new core_1.AccessControlError("Invalid action possession: \"" + action + "\"");
                valid = false;
                return false; // break out of loop
            }
            var perms = o[action];
            if (!utils.isEmptyArray(perms) && !utils.isFilledStringArray(perms)) {
                if (throwOnInvalid)
                    throw new core_1.AccessControlError("Invalid resource attributes for action \"" + action + "\".");
                valid = false;
                return false; // break out of loop
            }
            // suppress tslint warning
            return true; // continue
        });
        return valid;
    },
    /**
     *  Checks whether the given object is a valid role definition object.
     *
     *  @param {Object} o - Role definition to be checked.
     *  @param {String} roleName - Name of the role.
     *  @param {Boolean} [throwOnInvalid=true] - Specifies whether to throw if
     *  given object is not valid.
     *
     *  @returns {Boolean}
     *
     *  @throws {AccessControlError} - If `throwOnInvalid` is enabled and object
     *  is invalid.
     */
    validRoleObject: function (o, roleName, throwOnInvalid) {
        if (throwOnInvalid === void 0) { throwOnInvalid = true; }
        if (utils.type(o) !== 'object')
            return false;
        var valid = true;
        utils.eachKey(o, function (resourceName) {
            if (!utils.validName(resourceName, false)) {
                if (throwOnInvalid) {
                    throw new core_1.AccessControlError("Cannot use reserved name \"" + resourceName + "\" for a resource.");
                }
                valid = false;
                return false; // break out of loop
            }
            var resource = o[resourceName];
            if (!utils.validResourceObject(resource, throwOnInvalid)) {
                if (throwOnInvalid) {
                    throw new core_1.AccessControlError("Invalid resource definition (\"" + resourceName + "\") for role \"" + roleName + "\".");
                }
                valid = false;
                return false; // break out of loop
            }
            // suppress tslint warning
            return true; // continue
        });
        return true;
    },
    /**
     *  Inspects whether the given grants object has a valid structure and
     *  configuration; and returns a restructured grants object that can be used
     *  internally by AccessControl.
     *
     *  @param {Object|Array} o - Original grants object to be inspected.
     *
     *  @returns {Object} - Inspected, restructured grants object.
     *
     *  @throws {AccessControlError} - If given grants object has an invalid
     *  structure or configuration.
     */
    getInspectedGrants: function (o) {
        var grants = {};
        var strErr = 'Invalid grants object.';
        var type = utils.type(o);
        if (type === 'object') {
            utils.eachKey(o, function (key) {
                var role = o[key];
                // if $extend is found, it must be an array indicating inherited
                // roles, otherwise it's attempted to be used for a role name
                // which is invalid.
                if (key === '$extend') {
                    if (!utils.isEmptyArray(role) && !utils.isFilledStringArray(role)) {
                        throw new core_1.AccessControlError(strErr + " \"$extend\" is reserved for list of inherited roles.");
                    }
                }
                else if (key === '$') {
                    // "$" is reserved for a future feature. it's value will be an object.
                    throw new core_1.AccessControlError(strErr + " Cannot use reserved name \"" + key + "\".");
                }
                else if (!utils.validRoleObject(role, key)) {
                    throw new core_1.AccessControlError(strErr + " Definition of role \"" + key + "\" is invalid.");
                }
            });
            grants = o;
        }
        else if (type === 'array') {
            o.forEach(function (item) { return utils.commitToGrants(grants, item, true); });
        }
        else {
            throw new core_1.AccessControlError(strErr + " Expected an array or object.");
        }
        return grants;
    },
    // ----------------------
    // AC COMMON UTILS
    // ----------------------
    /**
     *  Normalizes the actions and possessions in the given `IQueryInfo` or
     *  `IAccessInfo`.
     *
     *  @param {IQueryInfo|IAccessInfo} info
     *
     *  @return {IQueryInfo|IAccessInfo}
     *
     *  @throws {AccessControlError} - If invalid action/possession found.
     */
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
    /**
     *  Normalizes the roles and resources in the given `IQueryInfo`.
     *
     *  @param {IQueryInfo} info
     *  @param {Boolean} [all=false] - Whether to validate all properties such
     *  as `action` and `possession`.
     *
     *  @return {IQueryInfo}
     *
     *  @throws {AccessControlError} - If invalid role/resource found.
     */
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
    /**
     *  Normalizes the roles and resources in the given `IAccessInfo`.
     *
     *  @param {IAccessInfo} info
     *  @param {Boolean} [all=false] - Whether to validate all properties such
     *  as `action` and `possession`.
     *
     *  @return {IQueryInfo}
     *
     *  @throws {AccessControlError} - If invalid role/resource found.
     */
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
     *  Gets a flat, ordered list of inherited roles for the given role.
     *  @param {Object} grants - Main grants object to be processed.
     *  @param {String} roleName - Role name to be inspected.
     *  @returns {Array<String>}
     */
    getInheritedRolesOf: function (grants, roleName) {
        var arr = [];
        var role = grants[roleName];
        if (!role)
            throw new core_1.AccessControlError("Role not found: \"" + roleName + "\"");
        arr = utils.pushUniq(arr, roleName);
        if (!Array.isArray(role.$extend) || role.$extend.length === 0)
            return arr;
        role.$extend.forEach(function (rName) {
            var ext = utils.getFlatRoles(grants, rName);
            arr = utils.uniqConcat(arr, ext);
        });
        return arr;
    },
    /**
     *  Gets roles and extended roles in a flat array.
     */
    getFlatRoles: function (grants, roles) {
        roles = utils.toStringArray(roles);
        if (!roles)
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(roles));
        var arr = utils.uniqConcat([], roles); // roles.concat();
        roles.forEach(function (roleName) {
            arr = utils.uniqConcat(arr, utils.getInheritedRolesOf(grants, roleName));
        });
        // console.log(`flat roles for ${roles}`, arr);
        return arr;
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
     *  Checks whether the given extender role is already (cross) inherited by
     *  the given role and returns the first cross-inherited role. Otherwise,
     *  returns `false`.
     *
     *  Note that cross-inheritance is not allowed.
     *
     *  @param {Any} grants - Grants model to be checked.
     *  @param {String} roles - Target role to be checked.
     *  @param {String|Array<String>} extenderRoles - Extender role(s) to be
     *  checked.
     *  @returns {Boolean}
     */
    getCrossInheritedRole: function (grants, role, extenderRoles) {
        var extenders = utils.toStringArray(extenderRoles);
        var crossInherited = false;
        utils.each(extenders, function (e) {
            if (crossInherited || role === e) {
                return false; // break out of loop
            }
            var inheritedByExtender = utils.getInheritedRolesOf(grants, e);
            utils.each(inheritedByExtender, function (r) {
                if (r === role) {
                    // get/report the parent role
                    crossInherited = e;
                    return false; // break out of loop
                }
                // suppress tslint warning
                return true; // continue
            });
            // suppress tslint warning
            return true; // continue
        });
        return crossInherited;
    },
    /**
     *  Extends the given role(s) with privileges of one or more other roles.
     *
     *  @param {Any} grants
     *  @param {String|Array<String>} roles Role(s) to be extended. Single role
     *         as a `String` or multiple roles as an `Array`. Note that if a
     *         role does not exist, it will be automatically created.
     *
     *  @param {String|Array<String>} extenderRoles Role(s) to inherit from.
     *         Single role as a `String` or multiple roles as an `Array`. Note
     *         that if a extender role does not exist, it will throw.
     *
     *  @throws {Error} If a role is extended by itself, a non-existent role or
     *          a cross-inherited role.
     */
    extendRole: function (grants, roles, extenderRoles) {
        var arrExtRoles = utils.toStringArray(extenderRoles).concat();
        if (!arrExtRoles)
            throw new core_1.AccessControlError("Cannot inherit invalid role(s): " + JSON.stringify(extenderRoles));
        var nonExistentExtRoles = utils.getNonExistentRoles(grants, arrExtRoles);
        if (nonExistentExtRoles.length > 0) {
            throw new core_1.AccessControlError("Cannot inherit non-existent role(s): \"" + nonExistentExtRoles.join(', ') + "\"");
        }
        roles = utils.toStringArray(roles);
        if (!roles)
            throw new core_1.AccessControlError("Invalid role(s): " + JSON.stringify(roles));
        roles.forEach(function (role) {
            if (arrExtRoles.indexOf(role) >= 0) {
                throw new core_1.AccessControlError("Attempted to extend role \"" + role + "\" by itself.");
            }
            // getCrossInheritedRole() returns false or the first
            // cross-inherited role, if found.
            var crossInherited = utils.getCrossInheritedRole(grants, role, arrExtRoles);
            if (crossInherited) {
                throw new core_1.AccessControlError("Role \"" + crossInherited + "\" already extends \"" + role + "\". Cross inheritance is not allowed.");
            }
            if (utils.validName(role)) {
                if (!grants.hasOwnProperty(role)) {
                    grants[role] = {
                        $extend: arrExtRoles
                    };
                }
                else {
                    var r = grants[role];
                    if (Array.isArray(r.$extend)) {
                        r.$extend = utils.uniqConcat(r.$extend, arrExtRoles);
                    }
                    else {
                        r.$extend = arrExtRoles;
                    }
                }
            }
        });
    },
    /**
     *  `utils.commitToGrants()` method already creates the roles but it's
     *  executed when the chain is terminated with either `.extend()` or an
     *  action method (e.g. `.createOwn()`). In case the chain is not
     *  terminated, we'll still (pre)create the role(s) with an empty object.
     *  @param {Any} grants
     *  @param {String|Array<String>} roles
     */
    preCreateRoles: function (grants, roles) {
        roles = utils.toStringArray(roles);
        roles.forEach(function (role) {
            if (utils.validName(role) && !grants.hasOwnProperty(role))
                grants[role] = {};
        });
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
            if (utils.validName(role) && !grants.hasOwnProperty(role)) {
                grants[role] = {};
            }
            var grantItem = grants[role];
            var ap = access.action + ':' + access.possession;
            access.resource.forEach(function (res) {
                if (utils.validName(res) && !grantItem.hasOwnProperty(res)) {
                    grantItem[res] = {};
                }
                // If possession (in action value or as a separate property) is
                // omitted, it will default to "any". e.g. "create" —>
                // "create:any"
                grantItem[res][ap] = utils.toStringArray(access.attributes);
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
     *  Locks the given AccessControl instance by freezing underlying grants
     *  model and disabling all functionality to modify it.
     *  @param {AccessControl} ac
     */
    lockAC: function (ac) {
        var _ac = ac; // ts
        if (!ac.isLocked || !Object.isFrozen(_ac._grants)) {
            utils.deepFreeze(_ac._grants);
            _ac._locked = true;
        }
    },
    // ----------------------
    // NOTATION/GLOB UTILS
    // ----------------------
    /**
     *  Deep clones the source object while filtering its properties by the
     *  given attributes (glob notations). Includes all matched properties and
     *  removes the rest.
     *
     *  @param {Object} object - Object to be filtered.
     *  @param {Array<String>} attributes - Array of glob notations.
     *
     *  @returns {Object} - Filtered object.
     */
    filter: function (object, attributes) {
        if (!Array.isArray(attributes) || attributes.length === 0) {
            return {};
        }
        var notation = new Notation(object);
        return notation.filter(attributes).value;
    },
    /**
     *  Deep clones the source array of objects or a single object while
     *  filtering their properties by the given attributes (glob notations).
     *  Includes all matched properties and removes the rest of each object in
     *  the array.
     *
     *  @param {Array|Object} arrOrObj - Array of objects or single object to be
     *  filtered.
     *  @param {Array<String>} attributes - Array of glob notations.
     *
     *  @returns {Array|Object}
     */
    filterAll: function (arrOrObj, attributes) {
        if (!Array.isArray(arrOrObj)) {
            return utils.filter(arrOrObj, attributes);
        }
        return arrOrObj.map(function (o) {
            return utils.filter(o, attributes);
        });
    }
};
exports.utils = utils;
