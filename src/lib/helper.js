// dep modules
import Notation from 'notation';
// own modules
import enums from '../enums';

const helper = {

    type(o) {
        return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
    },

    hasDefined(o, propName) {
        return o.hasOwnProperty(propName) && o[propName] !== undefined;
    },

    asArray(value, delim) {
        if (!value) return;
        if (Array.isArray(value)) return value;
        if (typeof value === 'string' && typeof delim === 'string') {
            return value.split(delim);
        }
        return [value];
    },

    uniqConcat(arrA, arrB) {
        arrB.forEach(b => {
            if (arrA.indexOf(b) < 0) arrA.push(b);
        });
        return arrA;
    },

    subtractArray(arrA, arrB) {
        return arrA.filter(a => arrB.indexOf(a) === -1);
    },

    eachKey(o, callback) {
        return Object.keys(o).forEach(callback);
    },

    // "create" + "own" = "createOwn"
    getMethodName(action, possession) {
        return action.toLowerCase()
            + possession.charAt(0).toUpperCase()
            + possession.slice(1).toLowerCase();
    },

    // Converts the given role(s) to an array, checks the role(s) and resource.
    normalizeRoleAndResource(o) {
        let valid = (typeof o.role === 'string' || Array.isArray(o.role))
            && o.role.length > 0;
        if (!valid) {
            throw new Error(`AccessControl: Invalid role(s): ${o.role}`);
        }
        o.role = helper.asArray(o.role);
        // o.role = valid ? _asArray(o.role) : [];

        valid = typeof o.resource === 'string' && o.resource.length > 0;
        if (!valid) {
            throw new Error(`AccessControl: Invalid resource: ${o.resource}`);
        }
        // o.resource = valid ? o.resource : '';
        return o;
    },

    // Normalizes base properties of an access object such as role, resource,
    // action and possession. This method also validates these properties and
    // throws if any of them is invalid.
    normalizeAccessObject(o) {
        o = helper.normalizeRoleAndResource(o);
        // when access is built (by user) via chain methods or by passing an
        // already defined object to the constructor (such as Grant, Deny
        // classes); the `action` and `possession` can be defined in 3 ways:
        // { action: 'create:any' }
        // equivalent to:
        // { action: 'create' } // possession defaults to 'any'
        // equivalent to:
        // { action: 'create', possession: 'any' }
        // The latter is also the normalized version for us to process.
        let ap = String(o.action || '').split(':'),
            a = ap[0].toLowerCase(),
            p = (o.possession || ap[1] || 'any').toLowerCase();
        if (enums.actions.indexOf(a) < 0) {
            throw new Error(`AccessControl: Invalid action: ${o.action}`);
        }
        if (enums.possessions.indexOf(String(p).toLowerCase()) < 0) {
            throw new Error(`AccessControl: Invalid action possession: ${p}`);
        }
        o.action = a;
        o.possession = p;
        return o;
    },

    filter(object, attributes) {
        if (!Array.isArray(attributes) || attributes.length === 0) {
            return {};
        }
        let notation = new Notation(object);
        return notation.filter(attributes).value();
    },

    filterAll(arrOrObj, attributes) {
        if (!Array.isArray(arrOrObj)) {
            return helper.filter(arrOrObj, attributes);
        }
        return arrOrObj.map(o => {
            return helper.filter(o, attributes);
        });
    }

};

export default helper;
