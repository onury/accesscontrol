// dep modules
import { Notation } from 'notation';
// own modules
import { AccessControl } from './';
import { Action, actions, Possession, possessions } from './enums';
import { IAccessInfo, IQueryInfo, AccessControlError } from './core';

/**
 *  List of reserved keywords.
 *  i.e. Roles, resources with these names are not allowed.
 */
const RESERVED_KEYWORDS = ['*', '!', '$', '$extend'];

/**
 *  Error message to be thrown after AccessControl instance is locked.
 */
const ERR_LOCK = 'Cannot alter the underlying grants model. AccessControl instance is locked.'

const utils = {

    // ----------------------
    // GENERIC UTILS
    // ----------------------

    /**
     *  Gets the type of the given object.
     *  @param {Any} o
     *  @returns {String}
     */
    type(o: any): string {
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
    hasDefined(o: any, propName: string): boolean {
        return o.hasOwnProperty(propName) && o[propName] !== undefined;
    },

    /**
     *  Converts the given (string) value into an array of string. Note that
     *  this does not throw if the value is not a string or array. It will
     *  silently return `[]` (empty array). So where ever it's used, the host
     *  function should consider throwing.
     *  @param {Any} value
     *  @returns {string[]}
     */
    toStringArray(value: any): string[] {
        if (Array.isArray(value)) return value;
        if (typeof value === 'string') return value.trim().split(/\s*[;,]\s*/);
        // throw new Error('Expected a string or array of strings, got ' + utils.type(value));
        return [];
    },

    /**
     *  Checks whether the given array consists of non-empty string items.
     *  (Array can be empty but no item should be an empty string.)
     *  @param {Array} arr - Array to be checked.
     *  @returns {Boolean}
     */
    isFilledStringArray(arr: any[]): boolean {
        if (!arr || !Array.isArray(arr)) return false;
        for (let s of arr) {
            if (typeof s !== 'string' || s.trim() === '') return false;
        }
        return true;
    },

    /**
     *  Checks whether the given value is an empty array.
     *  @param {Any} value - Value to be checked.
     *  @returns {Boolean}
     */
    isEmptyArray(value: any): boolean {
        return Array.isArray(value) && value.length === 0;
    },

    /**
     *  Ensures that the pushed item is unique in the target array.
     *  @param {Array} arr - Target array.
     *  @param {Any} item - Item to be pushed to array.
     *  @returns {Array}
     */
    pushUniq(arr: string[], item: string): string[] {
        if (arr.indexOf(item) < 0) arr.push(item);
        return arr;
    },

    /**
     *  Concats the given two arrays and ensures all items are unique.
     *  @param {Array} arrA
     *  @param {Array} arrB
     *  @returns {Array} - Concat'ed array.
     */
    uniqConcat(arrA: string[], arrB: string[]): string[] {
        const arr: string[] = arrA.concat();
        arrB.forEach((b: string) => {
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
    subtractArray(arrA: string[], arrB: string[]): string[] {
        return arrA.concat().filter(a => arrB.indexOf(a) === -1);
    },

    /**
     *  Deep freezes the given object.
     *  @param {Object} o - Object to be frozen.
     *  @returns {Object} - Frozen object.
     */
    deepFreeze(o: any): any {
        // Object.freeze accepts also an array. But here, we only use this for
        // objects.
        if (utils.type(o) !== 'object') return;
        const props = Object.getOwnPropertyNames(o);
        // freeze deeper before self
        props.forEach((key: string) => {
            let sub = o[key];
            if (Array.isArray(sub)) Object.freeze(sub);
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
    each(array, callback, thisArg = null) {
        const length = array.length;
        let index = -1;
        while (++index < length) {
            if (callback.call(thisArg, array[index], index, array) === false) break;
        }
    },

    /**
     *  Iterates through the keys of the given object. Breaking out early is
     *  possible by returning `false`.
     *  @param object
     *  @param callback
     *  @param thisArg
     */
    eachKey(object, callback, thisArg = null) {
        // return Object.keys(o).forEach(callback);
        // forEach has no way to interrupt execution, short-circuit unless an
        // error is thrown. so we use this:
        utils.each(Object.keys(object), callback, thisArg);
    },

    // ----------------------
    // AC ITERATION UTILS
    // ----------------------

    eachRole(grants, callback: (role: any, roleName: string) => void) {
        utils.eachKey(grants, (name: string) => callback(grants[name], name));
    },

    /**
     *
     */
    eachRoleResource(grants, callback: (role: string, resource: string, resourceDefinition: any) => void) {
        let resources, resourceDefinition;
        utils.eachKey(grants, (role: string) => {
            resources = grants[role];
            utils.eachKey(resources, (resource: string) => {
                resourceDefinition = role[resource];
                callback(role, resource, resourceDefinition);
            });
        });
    },

    // ----------------------
    // AC VALIDATION UTILS
    // ----------------------

    /**
     *  Checks whether the given access info can be commited to grants model.
     *  @param {IAccessInfo|IQueryInfo} info
     *  @returns {Boolean}
     */
    isInfoFulfilled(info: IAccessInfo | IQueryInfo): boolean {
        return utils.hasDefined(info, 'role')
            && utils.hasDefined(info, 'action')
            && utils.hasDefined(info, 'resource');
    },

    /**
     *  Checks whether the given name can be used and is not a reserved keyword.
     *
     *  @param {string} name - Name to be checked.
     *  @param {boolean} [throwOnInvalid=true] - Specifies whether to throw if
     *  name is not valid.
     *
     *  @returns {Boolean}
     *
     *  @throws {AccessControlError} - If `throwOnInvalid` is enabled and name
     *  is invalid.
     */
    validName(name: string, throwOnInvalid: boolean = true): boolean {
        if (typeof name !== 'string' || name.trim() === '') {
            if (!throwOnInvalid) return false;
            throw new AccessControlError('Invalid name, expected a valid string.');
        }
        if (RESERVED_KEYWORDS.indexOf(name) >= 0) {
            if (!throwOnInvalid) return false;
            throw new AccessControlError(`Cannot use reserved name: "${name}"`);
        }
        return true;
    },

    /**
     *  Checks whether the given array does not contain a reserved keyword.
     *
     *  @param {string|string[]} list - Name(s) to be checked.
     *  @param {boolean} [throwOnInvalid=true] - Specifies whether to throw if
     *  name is not valid.
     *
     *  @returns {Boolean}
     *
     *  @throws {AccessControlError} - If `throwOnInvalid` is enabled and name
     *  is invalid.
     */
    hasValidNames(list: any, throwOnInvalid: boolean = true): boolean {
        let allValid = true;
        utils.each(utils.toStringArray(list), name => {
            if (!utils.validName(name, throwOnInvalid)) {
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
     *
     *  @returns {Boolean}
     *
     *  @throws {AccessControlError} - If `throwOnInvalid` is enabled and object
     *  is invalid.
     */
    validResourceObject(o: any): boolean {
        if (utils.type(o) !== 'object') {
            throw new AccessControlError(`Invalid resource definition.`);
        }

        utils.eachKey(o, action => {
            let s: string[] = action.split(':');
            if (actions.indexOf(s[0]) === -1) {
                throw new AccessControlError(`Invalid action: "${action}"`);
            }
            if (s[1] && possessions.indexOf(s[1]) === -1) {
                throw new AccessControlError(`Invalid action possession: "${action}"`);
            }
            let perms = o[action];
            if (!utils.isEmptyArray(perms) && !utils.isFilledStringArray(perms)) {
                throw new AccessControlError(`Invalid resource attributes for action "${action}".`);
            }
        });
        return true;
    },

    /**
     *  Checks whether the given object is a valid role definition object.
     *
     *  @param {Object} grants - Original grants object being inspected.
     *  @param {string} roleName - Name of the role.
     *
     *  @returns {Boolean}
     *
     *  @throws {AccessControlError} - If `throwOnInvalid` is enabled and object
     *  is invalid.
     */
    validRoleObject(grants: any, roleName: string): boolean {
        let role = grants[roleName];
        if (!role || utils.type(role) !== 'object') {
            throw new AccessControlError(`Invalid role definition.`);
        }

        utils.eachKey(role, (resourceName: string) => {
            if (!utils.validName(resourceName, false)) {
                if (resourceName === '$extend') {
                    let extRoles: string[] = role[resourceName]; // semantics
                    if (!utils.isFilledStringArray(extRoles)) {
                        throw new AccessControlError(`Invalid extend value for role "${roleName}": ${JSON.stringify(extRoles)}`);
                    } else {
                        // attempt to actually extend the roles. this will throw
                        // on failure.
                        utils.extendRole(grants, roleName, extRoles);
                    }
                } else {
                    throw new AccessControlError(`Cannot use reserved name "${resourceName}" for a resource.`);
                }
            } else {
                utils.validResourceObject(role[resourceName]); // throws on failure
            }
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
    getInspectedGrants(o: any): any {
        let grants = {};
        const strErr: string = 'Invalid grants object.';
        const type: string = utils.type(o);

        if (type === 'object') {
            utils.eachKey(o, (roleName: string) => {
                if (utils.validName(roleName)) { // throws on failure
                    return utils.validRoleObject(o, roleName); // throws on failure
                }
                /* istanbul ignore next */
                return false;
                // above is redundant, previous checks will already throw on
                // failure so we'll never need to break early from this.
            });
            grants = o;
        } else if (type === 'array') {
            o.forEach((item: any) => utils.commitToGrants(grants, item, true));
        } else {
            throw new AccessControlError(`${strErr} Expected an array or object.`);
        }

        return grants;
    },

    // ----------------------
    // AC COMMON UTILS
    // ----------------------

    /**
     *  Gets all the unique resources that are granted access for at
     *  least one role.
     *
     *  @returns {string[]}
     */
    getResources(grants: any): string[] {
        // using an object for unique list
        let resources: any = {};
        utils.eachRoleResource(grants, (role: string, resource: string, permissions: any) => {
            resources[resource] = null;
        });
        return Object.keys(resources);
    },

    /**
     *  Normalizes the actions and possessions in the given `IQueryInfo` or
     *  `IAccessInfo`.
     *
     *  @param {IQueryInfo|IAccessInfo} info
     *  @param {boolean} [asString=false]
     *
     *  @return {IQueryInfo|IAccessInfo|string}
     *
     *  @throws {AccessControlError} - If invalid action/possession found.
     */
    normalizeActionPossession(info: IQueryInfo | IAccessInfo, asString: boolean = false): IQueryInfo | IAccessInfo | string {
        // validate and normalize action
        if (typeof info.action !== 'string') {
            // throw new AccessControlError(`Invalid action: ${info.action}`);
            throw new AccessControlError(`Invalid action: ${JSON.stringify(info)}`);
        }

        const s: string[] = info.action.split(':');
        if (actions.indexOf(s[0].trim().toLowerCase()) < 0) {
            throw new AccessControlError(`Invalid action: ${s[0]}`);
        }
        info.action = s[0].trim().toLowerCase();

        // validate and normalize possession
        const poss: string = info.possession || s[1];
        if (poss) {
            if (possessions.indexOf(poss.trim().toLowerCase()) < 0) {
                throw new AccessControlError(`Invalid action possession: ${poss}`);
            } else {
                info.possession = poss.trim().toLowerCase();
            }
        } else {
            // if no possession is set, we'll default to "any".
            info.possession = Possession.ANY;
        }

        return asString
            ? info.action + ':' + info.possession
            : info;
    },

    /**
     *  Normalizes the roles and resources in the given `IQueryInfo`.
     *
     *  @param {IQueryInfo} info
     *
     *  @return {IQueryInfo}
     *
     *  @throws {AccessControlError} - If invalid role/resource found.
     */
    normalizeQueryInfo(query: IQueryInfo): IQueryInfo {
        if (utils.type(query) !== 'object') {
            throw new AccessControlError(`Invalid IQueryInfo: ${typeof query}`);
        }
        // clone the object
        query = Object.assign({}, query);
        // validate and normalize role(s)
        query.role = utils.toStringArray(query.role);
        if (!utils.isFilledStringArray(query.role)) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(query.role)}`);
        }

        // validate resource
        if (typeof query.resource !== 'string' || query.resource.trim() === '') {
            throw new AccessControlError(`Invalid resource: "${query.resource}"`);
        }
        query.resource = query.resource.trim();
        query = utils.normalizeActionPossession(query) as IQueryInfo;

        return query;
    },

    /**
     *  Normalizes the roles and resources in the given `IAccessInfo`.
     *
     *  @param {IAccessInfo} info
     *  @param {boolean} [all=false] - Whether to validate all properties such
     *  as `action` and `possession`.
     *
     *  @return {IQueryInfo}
     *
     *  @throws {AccessControlError} - If invalid role/resource found.
     */
    normalizeAccessInfo(access: IAccessInfo, all: boolean = false): IAccessInfo {
        if (utils.type(access) !== 'object') {
            throw new AccessControlError(`Invalid IAccessInfo: ${typeof access}`);
        }
        // clone the object
        access = Object.assign({}, access);
        // validate and normalize role(s)
        access.role = utils.toStringArray(access.role);
        if (access.role.length === 0 || !utils.isFilledStringArray(access.role)) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(access.role)}`);
        }

        // validate and normalize resource
        access.resource = utils.toStringArray(access.resource);
        if (access.resource.length === 0 || !utils.isFilledStringArray(access.resource)) {
            throw new AccessControlError(`Invalid resource(s): ${JSON.stringify(access.resource)}`);
        }

        // normalize attributes
        if (access.denied || (Array.isArray(access.attributes) && access.attributes.length === 0)) {
            access.attributes = [];
        } else {
            // if omitted and not denied, all attributes are allowed
            access.attributes = !access.attributes ? ['*'] : utils.toStringArray(access.attributes);
        }

        // this part is not necessary if this is invoked from a comitter method
        // such as `createAny()`. So we'll check if we need to validate all
        // properties such as `action` and `possession`.
        if (all) access = utils.normalizeActionPossession(access) as IAccessInfo;

        return access;
    },

    /**
     *  Used to re-set (prepare) the `attributes` of an `IAccessInfo` object
     *  when it's first initialized with e.g. `.grant()` or `.deny()` chain
     *  methods.
     *  @param {IAccessInfo} access
     *  @returns {IAccessInfo}
     */
    resetAttributes(access: IAccessInfo): IAccessInfo {
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
     *  @param {string} roleName - Role name to be inspected.
     *  @returns {string[]}
     */
    getRoleHierarchyOf(grants: any, roleName: string, rootRole?: string): string[] {
        // `rootRole` is for memory storage. Do NOT set it when using;
        // and do NOT document this paramter.
        // rootRole = rootRole || roleName;

        const role: any = grants[roleName];
        if (!role) throw new AccessControlError(`Role not found: "${roleName}"`);

        let arr: string[] = [roleName];
        if (!Array.isArray(role.$extend) || role.$extend.length === 0) return arr;

        role.$extend.forEach((exRoleName: string) => {
            if (!grants[exRoleName]) {
                throw new AccessControlError(`Role not found: "${grants[exRoleName]}"`);
            }
            if (exRoleName === roleName) {
                throw new AccessControlError(`Cannot extend role "${roleName}" by itself.`);
            }
            // throw if cross-inheritance and also avoid memory leak with
            // maximum call stack error
            if (rootRole && (rootRole === exRoleName)) {
                throw new AccessControlError(`Cross inheritance is not allowed. Role "${exRoleName}" already extends "${rootRole}".`);
            }
            let ext: string[] = utils.getRoleHierarchyOf(grants, exRoleName, rootRole || roleName);
            arr = utils.uniqConcat(arr, ext);
        });
        return arr;
    },

    /**
     *  Gets roles and extended roles in a flat array.
     */
    getFlatRoles(grants: any, roles: string | string[]): string[] {
        const arrRoles: string[] = utils.toStringArray(roles);
        if (arrRoles.length === 0) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(roles)}`);
        }
        let arr: string[] = utils.uniqConcat([], arrRoles); // roles.concat();
        arrRoles.forEach((roleName: string) => {
            arr = utils.uniqConcat(arr, utils.getRoleHierarchyOf(grants, roleName));
        });
        // console.log(`flat roles for ${roles}`, arr);
        return arr;
    },

    /**
     *  Checks the given grants model and gets an array of non-existent roles
     *  from the given roles.
     *  @param {Any} grants - Grants model to be checked.
     *  @param {string[]} roles - Roles to be checked.
     *  @returns {string[]} - Array of non-existent roles. Empty array if
     *  all exist.
     */
    getNonExistentRoles(grants: any, roles: string[]) {
        let non: string[] = [];
        if (utils.isEmptyArray(roles)) return non;
        for (let role of roles) {
            if (!grants.hasOwnProperty(role)) non.push(role);
        }
        return non;
    },

    /**
     *  Checks whether the given extender role(s) is already (cross) inherited
     *  by the given role and returns the first cross-inherited role. Otherwise,
     *  returns `false`.
     *
     *  Note that cross-inheritance is not allowed.
     *
     *  @param {Any} grants - Grants model to be checked.
     *  @param {string} roles - Target role to be checked.
     *  @param {string|string[]} extenderRoles - Extender role(s) to be checked.
     *
     *  @returns {string|null} - Returns the first cross extending role. `null`
     *  if none.
     */
    getCrossExtendingRole(grants: any, roleName: string, extenderRoles: string | string[]): string {
        const extenders: string[] = utils.toStringArray(extenderRoles);
        let crossInherited: any = null;
        utils.each(extenders, (e: string) => {
            if (crossInherited || roleName === e) {
                return false; // break out of loop
            }
            const inheritedByExtender = utils.getRoleHierarchyOf(grants, e);
            utils.each(inheritedByExtender, (r: string) => {
                if (r === roleName) {
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
     *  @param {string|string[]} roles Role(s) to be extended. Single role
     *         as a `String` or multiple roles as an `Array`. Note that if a
     *         role does not exist, it will be automatically created.
     *
     *  @param {string|string[]} extenderRoles Role(s) to inherit from.
     *         Single role as a `String` or multiple roles as an `Array`. Note
     *         that if a extender role does not exist, it will throw.
     *
     *  @throws {Error} If a role is extended by itself, a non-existent role or
     *          a cross-inherited role.
     */
    extendRole(grants: any, roles: string | string[], extenderRoles: string | string[]) {
        // roles cannot be omitted or an empty array
        roles = utils.toStringArray(roles);
        if (roles.length === 0) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(roles)}`);
        }

        // extenderRoles cannot be omitted or but can be an empty array
        if (utils.isEmptyArray(extenderRoles)) return;

        const arrExtRoles: string[] = utils.toStringArray(extenderRoles).concat();
        if (arrExtRoles.length === 0) {
            throw new AccessControlError(`Cannot inherit invalid role(s): ${JSON.stringify(extenderRoles)}`);
        }

        const nonExistentExtRoles: string[] = utils.getNonExistentRoles(grants, arrExtRoles);
        if (nonExistentExtRoles.length > 0) {
            throw new AccessControlError(`Cannot inherit non-existent role(s): "${nonExistentExtRoles.join(', ')}"`);
        }

        roles.forEach((roleName: string) => {
            if (!grants[roleName]) throw new AccessControlError(`Role not found: "${roleName}"`);

            if (arrExtRoles.indexOf(roleName) >= 0) {
                throw new AccessControlError(`Cannot extend role "${roleName}" by itself.`);
            }

            // getCrossExtendingRole() returns false or the first
            // cross-inherited role, if found.
            let crossInherited: string = utils.getCrossExtendingRole(grants, roleName, arrExtRoles);
            if (crossInherited) {
                throw new AccessControlError(`Cross inheritance is not allowed. Role "${crossInherited}" already extends "${roleName}".`);
            }

            utils.validName(roleName); // throws if false
            let r = grants[roleName];
            if (Array.isArray(r.$extend)) {
                r.$extend = utils.uniqConcat(r.$extend, arrExtRoles);
            } else {
                r.$extend = arrExtRoles;
            }
        });
    },

    /**
     *  `utils.commitToGrants()` method already creates the roles but it's
     *  executed when the chain is terminated with either `.extend()` or an
     *  action method (e.g. `.createOwn()`). In case the chain is not
     *  terminated, we'll still (pre)create the role(s) with an empty object.
     *  @param {Any} grants
     *  @param {string|string[]} roles
     */
    preCreateRoles(grants: any, roles: string | string[]) {
        if (typeof roles === 'string') roles = utils.toStringArray(roles);
        if (!Array.isArray(roles) || roles.length === 0) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(roles)}`);
        }
        (roles as string[]).forEach((role: string) => {
            if (utils.validName(role) && !grants.hasOwnProperty(role)) {
                grants[role] = {};
            }
        });
    },

    /**
     *  Commits the given `IAccessInfo` object to the grants model.
     *  CAUTION: if attributes is omitted, it will default to `['*']` which
     *  means "all attributes allowed".
     *  @param {Any} grants
     *  @param {IAccessInfo} access
     *  @param {boolean} normalizeAll
     *         Specifies whether to validate and normalize all properties of
     *         the inner `IAccessInfo` object, including `action` and `possession`.
     *  @throws {Error} If `IAccessInfo` object fails validation.
     */
    commitToGrants(grants: any, access: IAccessInfo, normalizeAll: boolean = false) {
        access = utils.normalizeAccessInfo(access, normalizeAll);
        // console.log(access);
        // grant.role also accepts an array, so treat it like it.
        (access.role as string[]).forEach((role: string) => {
            if (utils.validName(role) && !grants.hasOwnProperty(role)) {
                grants[role] = {};
            }

            let grantItem: any = grants[role];
            let ap: string = access.action + ':' + access.possession;
            (access.resource as string[]).forEach((res: string) => {
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
     *  @returns {string[]} - Array of union'ed attributes.
     */
    getUnionAttrsOfRoles(grants: any, query: IQueryInfo): string[] {
        // throws if has any invalid property value
        query = utils.normalizeQueryInfo(query);

        let role;
        let resource: string;
        let attrsList: Array<string[]> = [];
        // get roles and extended roles in a flat array
        const roles: string[] = utils.getFlatRoles(grants, query.role);
        // iterate through roles and add permission attributes (array) of
        // each role to attrsList (array).
        roles.forEach((roleName: string, index: number) => {
            role = grants[roleName];
            // no need to check role existence #getFlatRoles() does that.

            resource = role[query.resource];
            if (resource) {
                // e.g. resource['create:own']
                // If action has possession "any", it will also return
                // `granted=true` for "own", if "own" is not defined.
                attrsList.push(
                    (resource[query.action + ':' + query.possession]
                        || resource[query.action + ':any']
                        || []).concat()
                );
                // console.log(resource, 'for:', action + '.' + possession);
            }
        });

        // union all arrays of (permitted resource) attributes (for each role)
        // into a single array.
        let attrs = [];
        const len: number = attrsList.length;
        if (len > 0) {
            attrs = attrsList[0];
            let i = 1;
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
    lockAC(ac: AccessControl) {
        const _ac = ac as any; // ts
        if (!_ac._grants || Object.keys(_ac._grants).length === 0) {
            throw new AccessControlError('Cannot lock empty or invalid grants model.');
        }

        let locked = ac.isLocked && Object.isFrozen(_ac._grants);
        if (!locked) locked = Boolean(utils.deepFreeze(_ac._grants));

        /* istanbul ignore next */
        if (!locked) {
            throw new AccessControlError(`Could not lock grants: ${typeof _ac._grants}`);
        }

        _ac._isLocked = locked;
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
     *  @param {string[]} attributes - Array of glob notations.
     *
     *  @returns {Object} - Filtered object.
     */
    filter(object: any, attributes: string[]): any {
        if (!Array.isArray(attributes) || attributes.length === 0) {
            return {};
        }
        const notation = new Notation(object);
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
     *  @param {string[]} attributes - Array of glob notations.
     *
     *  @returns {Array|Object}
     */
    filterAll(arrOrObj: any, attributes: string[]): any {
        if (!Array.isArray(arrOrObj)) {
            return utils.filter(arrOrObj, attributes);
        }
        return arrOrObj.map(o => {
            return utils.filter(o, attributes);
        });
    }

};

export {
    utils,
    RESERVED_KEYWORDS,
    ERR_LOCK
};
