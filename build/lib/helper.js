'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _notation = require('notation');

var _notation2 = _interopRequireDefault(_notation);

var _enums = require('../enums');

var _enums2 = _interopRequireDefault(_enums);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

// dep modules
var helper = {
    type: function type(o) {
        return Object.prototype.toString.call(o).match(/\s(\w+)/i)[1].toLowerCase();
    },
    hasDefined: function hasDefined(o, propName) {
        return o.hasOwnProperty(propName) && o[propName] !== undefined;
    },
    asArray: function asArray(value, delim) {
        if (!value) return;
        if (Array.isArray(value)) return value;
        if (typeof value === 'string' && typeof delim === 'string') {
            return value.split(delim);
        }
        return [value];
    },
    uniqConcat: function uniqConcat(arrA, arrB) {
        arrB.forEach(function (b) {
            if (arrA.indexOf(b) < 0) arrA.push(b);
        });
        return arrA;
    },
    subtractArray: function subtractArray(arrA, arrB) {
        return arrA.filter(function (a) {
            return arrB.indexOf(a) === -1;
        });
    },
    eachKey: function eachKey(o, callback) {
        return Object.keys(o).forEach(callback);
    },


    // "create" + "own" = "createOwn"
    getMethodName: function getMethodName(action, possession) {
        return action.toLowerCase() + possession.charAt(0).toUpperCase() + possession.slice(1).toLowerCase();
    },


    // Converts the given role(s) to an array, checks the role(s) and resource.
    normalizeRoleAndResource: function normalizeRoleAndResource(o) {
        var valid = (typeof o.role === 'string' || Array.isArray(o.role)) && o.role.length > 0;
        if (!valid) {
            throw new Error('AccessControl: Invalid role(s): ' + o.role);
        }
        o.role = helper.asArray(o.role);
        // o.role = valid ? _asArray(o.role) : [];

        valid = typeof o.resource === 'string' && o.resource.length > 0;
        if (!valid) {
            throw new Error('AccessControl: Invalid resource: ' + o.resource);
        }
        // o.resource = valid ? o.resource : '';
        return o;
    },


    // Normalizes base properties of an access object such as role, resource,
    // action and possession. This method also validates these properties and
    // throws if any of them is invalid.
    normalizeAccessObject: function normalizeAccessObject(o) {
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
        var ap = String(o.action || '').split(':'),
            a = ap[0].toLowerCase(),
            p = (o.possession || ap[1] || 'any').toLowerCase();
        if (_enums2.default.actions.indexOf(a) < 0) {
            throw new Error('AccessControl: Invalid action: ' + o.action);
        }
        if (_enums2.default.possessions.indexOf(String(p).toLowerCase()) < 0) {
            throw new Error('AccessControl: Invalid action possession: ' + p);
        }
        o.action = a;
        o.possession = p;
        return o;
    },
    filter: function filter(object, attributes) {
        if (!Array.isArray(attributes) || attributes.length === 0) {
            return {};
        }
        var notation = new _notation2.default(object);
        return notation.filter(attributes).value;
    },
    filterAll: function filterAll(arrOrObj, attributes) {
        if (!Array.isArray(arrOrObj)) {
            return helper.filter(arrOrObj, attributes);
        }
        return arrOrObj.map(function (o) {
            return helper.filter(o, attributes);
        });
    }
};
// own modules
exports.default = helper;
