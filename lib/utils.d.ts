import { AccessControl } from './';
import { IAccessInfo, IQueryInfo } from './core';
import type { ValidRole, ValidRoleOrArray } from '.';
/**
 *  List of reserved keywords.
 *  i.e. Roles, resources with these names are not allowed.
 */
declare const RESERVED_KEYWORDS: string[];
/**
 *  Error message to be thrown after AccessControl instance is locked.
 */
declare const ERR_LOCK = "Cannot alter the underlying grants model. AccessControl instance is locked.";
declare const utils: {
    /**
     *  Gets the type of the given object.
     *  @param {Any} o
     *  @returns {String}
     */
    type(o: any): string;
    /**
     *  Specifies whether the given value is set (other that `null` or
     *  `undefined`).
     *  @param {Any} o - Value to be checked.
     *  @returns {Boolean}
     */
    /**
     *  Specifies whether the property/key is defined on the given object.
     *  @param {Object} o
     *  @param {string} propName
     *  @returns {Boolean}
     */
    hasDefined(o: any, propName: string): boolean;
    /**
     *  Converts the given (string) value into an array of string. Note that
     *  this does not throw if the value is not a string or array. It will
     *  silently return `[]` (empty array). So where ever it's used, the host
     *  function should consider throwing.
     *  @param {Any} value
     *  @returns {string[]}
     */
    toValidRoleArray(value: unknown): ValidRole[];
    /**
     *  Checks whether the given array consists of non-empty string items.
     *  (Array can be empty but no item should be an empty string.)
     *  @param {Array} arr - Array to be checked.
     *  @returns {Boolean}
     */
    isFilledValidRoleArray(arr: unknown[]): arr is (string | number)[];
    isValidRole(e: unknown): e is string | number;
    /**
     *  Checks whether the given value is an empty array.
     *  @param {Any} value - Value to be checked.
     *  @returns {Boolean}
     */
    isEmptyArray(value: any): boolean;
    /**
     *  Ensures that the pushed item is unique in the target array.
     *  @param {Array} arr - Target array.
     *  @param {Any} item - Item to be pushed to array.
     *  @returns {Array}
     */
    pushUniq(arr: ValidRole[], item: ValidRole): ValidRole[];
    /**
     *  Concats the given two arrays and ensures all items are unique.
     *  @param {Array} arrA
     *  @param {Array} arrB
     *  @returns {Array} - Concat'ed array.
     */
    uniqConcat(arrA: ValidRole[], arrB: ValidRole[]): ValidRole[];
    /**
     *  Subtracts the second array from the first.
     *  @param {Array} arrA
     *  @param {Array} arrB
     *  @return {Array} - Resulting array.
     */
    subtractArray(arrA: ValidRole[], arrB: ValidRole[]): ValidRole[];
    /**
     *  Deep freezes the given object.
     *  @param {Object} o - Object to be frozen.
     *  @returns {Object} - Frozen object.
     */
    deepFreeze(o: any): any;
    /**
     *  Similar to JS .forEach, except this allows for breaking out early,
     *  (before all iterations are executed) by returning `false`.
     *  @param array
     *  @param callback
     *  @param thisArg
     */
    each(array: any, callback: any, thisArg?: any): void;
    /**
     *  Iterates through the keys of the given object. Breaking out early is
     *  possible by returning `false`.
     *  @param object
     *  @param callback
     *  @param thisArg
     */
    eachKey(object: any, callback: any, thisArg?: any): void;
    eachRole(grants: any, callback: (role: any, roleName: string) => void): void;
    /**
     *
     */
    eachRoleResource(grants: any, callback: (role: string, resource: string, resourceDefinition: any) => void): void;
    /**
     *  Checks whether the given access info can be commited to grants model.
     *  @param {IAccessInfo|IQueryInfo} info
     *  @returns {Boolean}
     */
    isInfoFulfilled(info: IAccessInfo | IQueryInfo): boolean;
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
    validName(name: ValidRole, throwOnInvalid?: boolean): boolean;
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
    hasValidNames(list: any, throwOnInvalid?: boolean): boolean;
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
    validResourceObject(o: any): boolean;
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
    validRoleObject(grants: any, roleName: string): boolean;
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
    getInspectedGrants(o: any): any;
    /**
     *  Gets all the unique resources that are granted access for at
     *  least one role.
     *
     *  @returns {string[]}
     */
    getResources(grants: any): string[];
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
    normalizeActionPossession(info: IQueryInfo | IAccessInfo, asString?: boolean): IQueryInfo | IAccessInfo | string;
    /**
     *  Normalizes the roles and resources in the given `IQueryInfo`.
     *
     *  @param {IQueryInfo} info
     *
     *  @return {IQueryInfo}
     *
     *  @throws {AccessControlError} - If invalid role/resource found.
     */
    normalizeQueryInfo(query: IQueryInfo): IQueryInfo;
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
    normalizeAccessInfo(access: IAccessInfo, all?: boolean): IAccessInfo;
    /**
     *  Used to re-set (prepare) the `attributes` of an `IAccessInfo` object
     *  when it's first initialized with e.g. `.grant()` or `.deny()` chain
     *  methods.
     *  @param {IAccessInfo} access
     *  @returns {IAccessInfo}
     */
    resetAttributes(access: IAccessInfo): IAccessInfo;
    /**
     *  Gets a flat, ordered list of inherited roles for the given role.
     *  @param {Object} grants - Main grants object to be processed.
     *  @param {string} roleName - Role name to be inspected.
     *  @returns {string[]}
     */
    getRoleHierarchyOf(grants: any, roleName: ValidRole, rootRole?: ValidRole): ValidRole[];
    /**
     *  Gets roles and extended roles in a flat array.
     */
    getFlatRoles(grants: any, roles: ValidRoleOrArray): ValidRole[];
    /**
     *  Checks the given grants model and gets an array of non-existent roles
     *  from the given roles.
     *  @param {Any} grants - Grants model to be checked.
     *  @param {string[]} roles - Roles to be checked.
     *  @returns {ValidRole[]} - Array of non-existent roles. Empty array if
     *  all exist.
     */
    getNonExistentRoles(grants: any, roles: ValidRole[]): (string | number)[];
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
    getCrossExtendingRole(grants: any, roleName: string, extenderRoles: ValidRoleOrArray): string;
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
    extendRole(grants: any, roles: ValidRoleOrArray, extenderRoles: ValidRoleOrArray): void;
    /**
     *  `utils.commitToGrants()` method already creates the roles but it's
     *  executed when the chain is terminated with either `.extend()` or an
     *  action method (e.g. `.createOwn()`). In case the chain is not
     *  terminated, we'll still (pre)create the role(s) with an empty object.
     *  @param {Any} grants
     *  @param {string|string[]} roles
     */
    preCreateRoles(grants: any, roles: ValidRoleOrArray): void;
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
    commitToGrants(grants: any, access: IAccessInfo, normalizeAll?: boolean): void;
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
    getUnionAttrsOfRoles(grants: any, query: IQueryInfo): string[];
    /**
     *  Locks the given AccessControl instance by freezing underlying grants
     *  model and disabling all functionality to modify it.
     *  @param {AccessControl} ac
     */
    lockAC(ac: AccessControl): void;
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
    filter(object: any, attributes: string[]): any;
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
    filterAll(arrOrObj: any, attributes: string[]): any;
};
export { utils, RESERVED_KEYWORDS, ERR_LOCK };
