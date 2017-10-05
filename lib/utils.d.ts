import { AccessControl } from './';
import { IAccessInfo, IQueryInfo } from './core';
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
    type(o: any): string;
    hasDefined(o: any, propName: string): boolean;
    toStringArray(value: any): string[];
    isFilledStringArray(arr: any[]): boolean;
    isStringOrArray(value: any): boolean;
    isEmptyArray(value: any): boolean;
    pushUniq(arr: string[], item: string): string[];
    uniqConcat(arrA: string[], arrB: string[]): string[];
    subtractArray(arrA: string[], arrB: string[]): string[];
    deepFreeze(o: any): any;
    each(array: any, callback: any, thisArg?: any): void;
    eachKey(object: any, callback: any): void;
    isInfoFulfilled(info: IAccessInfo | IQueryInfo): boolean;
    validName(name: string, throwOnInvalid?: boolean, msg?: string): boolean;
    hasValidNames(list: any, throwOnInvalid?: boolean, msg?: string): boolean;
    validResourceObject(o: any, throwOnInvalid?: boolean): boolean;
    validRoleObject(o: any, roleName: string, throwOnInvalid?: boolean): boolean;
    getInspectedGrants(o: any): any;
    normalizeActionPossession(info: IAccessInfo | IQueryInfo): IAccessInfo | IQueryInfo;
    normalizeQueryInfo(query: IQueryInfo, all?: boolean): IQueryInfo;
    normalizeAccessInfo(access: IAccessInfo, all?: boolean): IAccessInfo;
    resetAttributes(access: IAccessInfo): IAccessInfo;
    getInheritedRolesOf(grants: any, roleName: string): string[];
    getFlatRoles(grants: any, roles: string | string[]): string[];
    getNonExistentRoles(grants: any, roles: string[]): string[];
    getCrossInheritedRole(grants: any, role: string, extenderRoles: string | string[]): string | boolean;
    extendRole(grants: any, roles: string | string[], extenderRoles: string | string[]): void;
    preCreateRoles(grants: any, roles: string | string[]): void;
    commitToGrants(grants: any, access: IAccessInfo, normalizeAll?: boolean): void;
    getUnionAttrsOfRoles(grants: any, query: IQueryInfo): string[];
    lockAC(ac: AccessControl): void;
    filter(object: any, attributes: string[]): any;
    filterAll(arrOrObj: any, attributes: string[]): any;
};
export { utils, RESERVED_KEYWORDS, ERR_LOCK };
