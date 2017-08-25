// dep modules
import * as Notation from 'notation';
// own modules
import { Action, actions, Possession, possessions } from './enums';
import { IAccessInfo, IQueryInfo, AccessControlError } from './core';

const utils = {

    type(o:any):string {
        return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
    },

    hasDefined(o:any, propName:string):boolean {
        return o.hasOwnProperty(propName) && o[propName] !== undefined;
    },

    toStringArray(value:any):string[] {
        if (Array.isArray(value)) return value;
        if (typeof value === 'string') return value.trim().split(/\s*[;,]\s*/);
        throw new Error('Cannot convert value to array!');
    },

    isFilledStringArray(arr:any[]):boolean {
        for (let s of arr) {
           if (typeof s !== 'string' || s.trim() === '') return false;
        }
        return true;
    },

    isStringOrArray(value:any):boolean {
        return typeof value === 'string' || utils.isFilledStringArray(value);
    },

    isEmptyArray(value:any):boolean {
        return Array.isArray(value) && value.length === 0;
    },

    uniqConcat(arrA:string[], arrB:string[]):string[] {
        let arr:string[] = arrA.concat();
        arrB.forEach((b:string) => {
            if (arr.indexOf(b) < 0) arr.push(b);
        });
        return arr;
    },

    subtractArray(arrA:string[], arrB:string[]):string[] {
        return arrA.concat().filter(a => arrB.indexOf(a) === -1);
    },

    eachKey(o:any, callback:(key:string, index?:number) => void) {
        return Object.keys(o).forEach(callback);
    },

    /**
     *  Gets roles and extended roles in a flat array.
     */
    getFlatRoles(grants:any, roles:string|string[]):string[] {
        roles = utils.toStringArray(roles);
        let arr:string[] = roles.concat();
        roles.forEach((roleName:string) => {
            let role:any = grants[roleName];
            if (!role) throw new AccessControlError(`Role not found: "${roleName}"`);
            if (Array.isArray(role.$extend)) {
                arr = utils.uniqConcat(arr, role.$extend);
            }
        });
        return arr;
    },

    normalizeActionPossession(info:IQueryInfo|IAccessInfo):IQueryInfo|IAccessInfo {
        // validate and normalize action
        if (typeof info.action !== 'string') {
            throw new AccessControlError(`Invalid action: ${info.action}`);
        }

        let s:string[] = info.action.split(':');
        if (actions.indexOf(s[0].trim().toLowerCase()) < 0) {
            throw new AccessControlError(`Invalid action: ${s[0]}`);
        }
        info.action = s[0].trim().toLowerCase();

        // validate and normalize possession
        let poss:string = info.possession || s[1];
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

        return info;
    },

    normalizeQueryInfo(query:IQueryInfo, all:boolean = false):IQueryInfo {
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

        // this part is not necessary if this is invoked from a comitter method
        // such as `createAny()`. So we'll check if we need to validate all
        // properties such as `action` and `possession`.
        if (all) query = utils.normalizeActionPossession(query) as IQueryInfo;

        return query;
    },

    normalizeAccessInfo(access:IAccessInfo, all:boolean = false):IAccessInfo {
        // clone the object
        access = Object.assign({}, access);
        // validate and normalize role(s)
        access.role = utils.toStringArray(access.role);
        if (!utils.isFilledStringArray(access.role)) {
            throw new AccessControlError(`Invalid role(s): ${JSON.stringify(access.role)}`);
        }

        // validate and normalize resource
        access.resource = utils.toStringArray(access.resource);
        if (!utils.isFilledStringArray(access.resource)) {
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
    resetAttributes(access:IAccessInfo):IAccessInfo {
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
    isInfoFulfilled(info:IAccessInfo|IQueryInfo):boolean {
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
    commitToGrants(grants:any, access:IAccessInfo, normalizeAll:boolean = false) {
        access = utils.normalizeAccessInfo(access, normalizeAll);
        // console.log(access);
        // grant.role also accepts an array, so treat it like it.
        (access.role as Array<string>).forEach((role:string) => {
            if (!grants.hasOwnProperty(role)) grants[role] = {};
            let grantItem:any = grants[role];

            let ap:string = access.action + ':' + access.possession;
            (access.resource as Array<string>).forEach((res:string) => {
                if (!grantItem.hasOwnProperty(res)) grantItem[res] = {};
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
    getUnionAttrsOfRoles(grants:any, query:IQueryInfo):string[] {
        if (!grants) {
            throw new AccessControlError('Grants are not set.');
        }
        // throws if has any invalid property value
        query = utils.normalizeQueryInfo(query);

        let grantItem;
        let resource:string;
        let attrsList:Array<string[]> = [];
        // get roles and extended roles in a flat array
        let roles:string[] = utils.getFlatRoles(grants, query.role);
        // iterate through roles and add permission attributes (array) of
        // each role to attrsList (array).
        roles.forEach((role:string, index:number) => {
            grantItem = grants[role];
            if (grantItem) {
                resource = grantItem[query.resource];
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
            }
        });

        // union all arrays of (permitted resource) attributes (for each role)
        // into a single array.
        let attrs = [];
        let len:number = attrsList.length;
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
     *  Checks the given grants model and gets an array of non-existent roles
     *  from the given roles.
     *  @param {Any} grants - Grants model to be checked.
     *  @param {Array<string>} roles - Roles to be checked.
     *  @returns {Array<String>} - Array of non-existent roles. Empty array if
     *  all exist.
     */
    getNonExistentRoles(grants:any, roles:string[]) {
        let non:string[] = [];
        for (let role of roles) {
            if (!grants.hasOwnProperty(role)) non.push(role);
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
    extendRole(grants:any, roles:string|string[], extenderRoles:string|string[]) {
        let arrExtRoles:string[] = utils.toStringArray(extenderRoles);
        let nonExistentExtRoles:string[] = utils.getNonExistentRoles(grants, arrExtRoles);
        if (nonExistentExtRoles.length > 0) {
            throw new AccessControlError(`Cannot extend with non-existent role(s): "${nonExistentExtRoles.join(', ')}"`);
        }

        utils.toStringArray(roles).forEach((role:string) => {
            if (arrExtRoles.indexOf(role) >= 0) {
                throw new AccessControlError(`Attempted to extend role "${role}" by itself.`);
            }
            if (!grants.hasOwnProperty(role)) {
                grants[role] = {
                    $extend: arrExtRoles.concat()
                };
            } else {
                let r = grants[role];
                if (Array.isArray(r.$extend)) {
                    r.$extend = utils.uniqConcat(r.$extend, arrExtRoles);
                } else {
                    r.$extend = arrExtRoles.concat();
                }
            }
        });
    },

    filter(object:any, attributes:string[]):any {
        if (!Array.isArray(attributes) || attributes.length === 0) {
            return {};
        }
        let notation = new Notation(object);
        return notation.filter(attributes).value;
    },

    filterAll(arrOrObj:any, attributes:string[]):any {
        if (!Array.isArray(arrOrObj)) {
            return utils.filter(arrOrObj, attributes);
        }
        return arrOrObj.map(o => {
            return utils.filter(o, attributes);
        });
    }

};

export default utils;
