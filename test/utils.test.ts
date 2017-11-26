'use strict';

/**
 *  Test Suite: AccessControl
 *
 *  This suite mostly includes generic methods of the utils class. Most core
 *  methods (directly related with AccessControl) are tested via `ac.test.ts`.
 *
 *  @author   Onur Yıldırım <onur@cutepilot.com>
 */


import { AccessControl } from '../src';
import { IQueryInfo } from '../src/core';
import { utils, RESERVED_KEYWORDS } from '../src/utils';
// test helper
import { helper } from './helper';

describe('Test Suite: utils (generic)', () => {

    test('#type()', () => {
        expect(utils.type(undefined)).toEqual('undefined');
        expect(utils.type(null)).toEqual('null');
        expect(utils.type({})).toEqual('object');
        expect(utils.type([])).toEqual('array');
        expect(utils.type('')).toEqual('string');
        expect(utils.type(1)).toEqual('number');
        expect(utils.type(true)).toEqual('boolean');
    });

    test('#hasDefined()', () => {
        const o = { prop: 1, def: undefined };
        expect(utils.hasDefined(o, 'prop')).toBe(true);
        expect(utils.hasDefined(o, 'def')).toBe(false);
        expect(utils.hasDefined(o, 'none')).toBe(false);
        expect(() => utils.hasDefined(null, 'prop')).toThrow();
    });

    test('#toStringArray()', () => {
        expect(utils.toStringArray([])).toEqual([]);
        expect(utils.toStringArray('a')).toEqual(['a']);
        expect(utils.toStringArray('a,b,c')).toEqual(['a', 'b', 'c']);
        expect(utils.toStringArray('a, b,  c  \n')).toEqual(['a', 'b', 'c']);
        expect(utils.toStringArray('a ; b,c')).toEqual(['a', 'b', 'c']);
        expect(utils.toStringArray('a;b; c')).toEqual(['a', 'b', 'c']);
        expect(utils.toStringArray(1)).toEqual([]);
        expect(utils.toStringArray(true)).toEqual([]);
        expect(utils.toStringArray(false)).toEqual([]);
        expect(utils.toStringArray(null)).toEqual([]);
        expect(utils.toStringArray(undefined)).toEqual([]);
    });

    test('#isFilledStringArray(), #isEmptyArray()', () => {
        expect(utils.isFilledStringArray([])).toBe(true); // allowed
        expect(utils.isFilledStringArray([''])).toBe(false);
        expect(utils.isFilledStringArray(['a'])).toBe(true);
        expect(utils.isFilledStringArray(['a', ''])).toBe(false);
        expect(utils.isFilledStringArray([1])).toBe(false);
        expect(utils.isFilledStringArray([null])).toBe(false);
        expect(utils.isFilledStringArray([undefined])).toBe(false);
        expect(utils.isFilledStringArray([false])).toBe(false);

        expect(utils.isEmptyArray([])).toBe(true);
        expect(utils.isEmptyArray([1])).toBe(false);
        expect(utils.isEmptyArray([''])).toBe(false);
        expect(utils.isEmptyArray([null])).toBe(false);
        expect(utils.isEmptyArray([undefined])).toBe(false);
        expect(utils.isEmptyArray('[]')).toBe(false);
        expect(utils.isEmptyArray(1)).toBe(false);
        expect(utils.isEmptyArray(null)).toBe(false);
        expect(utils.isEmptyArray(undefined)).toBe(false);
        expect(utils.isEmptyArray(true)).toBe(false);
    });

    test('#pushUniq(), #uniqConcat(), #subtractArray()', () => {
        const original = ['a', 'b', 'c'];
        const arr = original.concat();
        expect(utils.pushUniq(arr, 'a')).toEqual(original);
        expect(utils.pushUniq(arr, 'd')).toEqual(original.concat(['d']));

        expect(utils.uniqConcat(original, ['a'])).toEqual(original);
        expect(utils.uniqConcat(original, ['d'])).toEqual(original.concat(['d']));

        expect(utils.subtractArray(original, ['a'])).toEqual(['b', 'c']);
        expect(utils.subtractArray(original, ['d'])).toEqual(original);
    });

    test('#deepFreeze()', () => {
        expect((utils as any).deepFreeze()).toBeUndefined();
        const o = {
            x: 1,
            inner: {
                x: 2
            }
        };
        expect(utils.deepFreeze(o)).toEqual(expect.any(Object));
        expect(() => o.x = 5).toThrow();
        expect(() => (o as any).inner = {}).toThrow();
        expect(() => o.inner.x = 6).toThrow();
    });

    test('#each(), #eachKey()', () => {
        const original: number[] = [1, 2, 3];
        let items: number[] = [];
        utils.each(original, (item: number) => items.push(item));
        expect(items).toEqual(original);

        items = [];

        // break out early by returning false

        utils.each(original, (item: number) => {
            items.push(item);
            return item < 2;
        });
        expect(items).toEqual([1, 2]);

        const o = { x: 0, y: 1, z: 2 };
        const d = {};
        utils.eachKey(o, (key: string, index: number) => {
            d[key] = index;
        });
        expect(d).toEqual(o);

        // test thisArg

        function Context() {
            this.ok = true;
        }

        utils.each([1], function (item: number) {
            expect(this.ok).toBe(true);
        }, new Context());

        utils.eachKey({ key: 1 }, function (key: string) {
            expect(this.ok).toBe(true);
        }, new Context());
    });

});

describe('Test Suite: utils (core)', () => {

    // ------------------------------------------
    // NOTE: other parts of these methods should be covered in other tests.
    // check coverage report.
    // ------------------------------------------

    test('#validName(), #hasValidNames()', () => {
        let valid: any = 'someName';
        expect(utils.validName(valid)).toBe(true);
        expect(utils.validName(valid, false)).toBe(true);
        expect(utils.validName(valid, false)).toBe(true);

        let invalid: any = RESERVED_KEYWORDS[0];
        helper.expectACError(() => utils.validName(invalid));
        helper.expectACError(() => utils.validName(invalid, true));
        expect(utils.validName(invalid, false)).toBe(false);
        expect(utils.validName('', false)).toBe(false);
        expect((utils as any).validName(1, false)).toBe(false);
        expect((utils as any).validName(null, false)).toBe(false);
        expect((utils as any).validName(true, false)).toBe(false);

        valid = ['valid', 'name'];
        expect(utils.hasValidNames(valid)).toBe(true);
        expect(utils.hasValidNames(valid, false)).toBe(true);
        expect(utils.hasValidNames(valid, false)).toBe(true);

        invalid = ['valid', RESERVED_KEYWORDS[RESERVED_KEYWORDS.length - 1]];
        helper.expectACError(() => utils.hasValidNames(invalid));
        helper.expectACError(() => utils.hasValidNames(invalid, true));
        expect(utils.hasValidNames(invalid, false)).toBe(false);
    });

    test('#validResourceObject()', () => {
        helper.expectACError(() => utils.validResourceObject(null));
        helper.expectACError(() => utils.validResourceObject(null));
        expect(utils.validResourceObject({ 'create': [] })).toBe(true);
        expect(utils.validResourceObject({ 'create:any': ['*', '!id'] })).toBe(true);
        expect(utils.validResourceObject({ 'update:own': ['*'] })).toBe(true);

        helper.expectACError(() => utils.validResourceObject({ 'invalid': [], 'create': [] }));
        helper.expectACError(() => utils.validResourceObject({ 'invalid:any': [] }));
        helper.expectACError(() => utils.validResourceObject({ 'invalid:any': [''] }));
        helper.expectACError(() => utils.validResourceObject({ 'read:own': ['*'], 'invalid:own': [] }));

        helper.expectACError(() => utils.validResourceObject({ 'create:all': [] }));
        helper.expectACError(() => utils.validResourceObject({ 'create:all': [] }));

        helper.expectACError(() => utils.validResourceObject({ 'create': null }));
        helper.expectACError(() => utils.validResourceObject({ 'create:own': undefined }));
        helper.expectACError(() => utils.validResourceObject({ 'read:own': [], 'create:any': [''] }));
        helper.expectACError(() => utils.validResourceObject({ 'create:any': ['*', ''] }));
    });

    test('#validRoleObject()', () => {
        let grants: any = { 'admin': { 'account': { 'read:any': ['*'] } } };
        expect(utils.validRoleObject(grants, 'admin')).toBe(true);
        grants.admin = { 'account': ['*'] };
        helper.expectACError(() => utils.validRoleObject(grants, 'admin'));
        grants.admin = { 'account': { 'read:own': ['*'] } };
        expect(() => utils.validRoleObject(grants, 'admin')).not.toThrow();
        grants.admin = { 'account': { 'read': ['*'] } };
        expect(() => utils.validRoleObject(grants, 'admin')).not.toThrow();
        grants.admin = { 'account': { 'read:all': ['*'] } };
        helper.expectACError(() => utils.validRoleObject(grants, 'admin'));
        grants.admin = { '$extend': ['*'] }; // cannot inherit non-existent role(s)
        helper.expectACError(() => utils.validRoleObject(grants, 'admin'));

        grants.user = { 'account': { 'read:own': ['*'] } };
        grants.admin = { '$extend': ['user'] };
        expect(() => utils.validRoleObject(grants, 'admin')).not.toThrow();
        grants.admin = { '$': { 'account': { 'read:own': ['*'] } } }; // $: reserved
        helper.expectACError(() => utils.validRoleObject(grants, 'admin'));
        grants.admin = { 'account': [] }; // invalid resource structure
        helper.expectACError(() => utils.validRoleObject(grants, 'admin'));
        grants.admin = { 'account': { 'read:own': [''] } }; // invalid resource structure
        helper.expectACError(() => utils.validRoleObject(grants, 'admin'));
        grants.admin = { 'account': null }; // invalid resource structure
        helper.expectACError(() => utils.validRoleObject(grants, 'admin'));
    });

    test('#normalizeQueryInfo(), #normalizeAccessInfo()', () => {
        helper.expectACError(() => utils.normalizeQueryInfo(null));
        helper.expectACError(() => utils.normalizeQueryInfo({ role: null }));
        helper.expectACError(() => (utils as any).normalizeQueryInfo({ role: 1 }));
        helper.expectACError(() => utils.normalizeQueryInfo({ role: [] }));
        helper.expectACError(() => utils.normalizeQueryInfo({ role: '' }));
        helper.expectACError(() => utils.normalizeQueryInfo({ role: 'sa', resource: '' }));
        helper.expectACError(() => (utils as any).normalizeQueryInfo({ role: 'sa', resource: null }));
        helper.expectACError(() => (utils as any).normalizeQueryInfo({ role: 'sa', resource: [] }));

        helper.expectACError(() => utils.normalizeAccessInfo(null));
        helper.expectACError(() => utils.normalizeAccessInfo({ role: null }));
        helper.expectACError(() => utils.normalizeAccessInfo({ role: [] }));
        helper.expectACError(() => utils.normalizeAccessInfo({ role: '' }));
        helper.expectACError(() => (utils as any).normalizeAccessInfo({ role: 1 }));
        helper.expectACError(() => utils.normalizeAccessInfo({ role: 'sa', resource: '' }));
        helper.expectACError(() => (utils as any).normalizeAccessInfo({ role: 'sa', resource: null }));
        helper.expectACError(() => (utils as any).normalizeAccessInfo({ role: 'sa', resource: [] }));
    });

    test('#getRoleHierarchyOf()', () => {
        let grants: any = {
            'admin': {
                '$extend': ['user']
                // 'account': { 'read:any': ['*'] }
            }
        };
        helper.expectACError(() => utils.getRoleHierarchyOf(grants, 'admin'));
        grants.admin = { '$extend': ['admin'] };
        helper.expectACError(() => utils.getRoleHierarchyOf(grants, 'admin'));

        grants.admin = { 'account': { 'read:any': ['*'] } };
        helper.expectACError(() => utils.getRoleHierarchyOf(grants, null));
        helper.expectACError(() => utils.getRoleHierarchyOf(grants, ''));
    });

    test('#getFlatRoles()', () => {
        helper.expectACError(() => utils.getFlatRoles({}, null));
        helper.expectACError(() => utils.getFlatRoles({}, ''));
    });

    test('#getNonExistentRoles()', () => {
        let grants: any = {
            'admin': {
                'account': { 'read:any': ['*'] }
            }
        };
        expect(utils.getNonExistentRoles(grants, [])).toEqual([]);
        expect(utils.getNonExistentRoles(grants, [''])).toEqual(['']);
    });

    test('#getCrossExtendingRole()', () => {
        let grants: any = {
            'user': {},
            'admin': {
                '$extend': ['user', 'editor']
            },
            'editor': {
                '$extend': ['admin']
            },
        };
        expect(utils.getCrossExtendingRole(grants, 'admin', ['admin'])).toEqual(null);
        expect(utils.getCrossExtendingRole(grants, 'admin', ['user'])).toEqual(null);
        helper.expectACError(() => utils.getCrossExtendingRole(grants, 'user', ['admin']));
    });

    test('#extendRole()', () => {
        let grants: any = {
            'user': {},
            'admin': {
                '$extend': ['user', 'editor']
            },
            'editor': {
                '$extend': ['admin']
            },
            'viewer': {}
        };
        helper.expectACError(() => utils.extendRole(grants, null, ['admin']));
        helper.expectACError(() => utils.extendRole(grants, 'admin', null));
        helper.expectACError(() => utils.extendRole(grants, 'nonexisting', 'user'));
        helper.expectACError(() => utils.extendRole(grants, 'admin', 'nonexisting'));
        helper.expectACError(() => utils.extendRole(grants, 'admin', 'editor')); // cross
        helper.expectACError(() => utils.extendRole(grants, '$', 'user')); // reserved keyword
        expect(() => utils.extendRole(grants, 'admin', 'viewer')).not.toThrow();
    });

    test('#getUnionAttrsOfRoles()', () => {
        let grants: any = {
            'user': {
                'account': {
                    'read:own': ['*']
                }
            },
            'admin': {
                '$extend': ['user']
            }
        };
        let query: IQueryInfo = {
            role: 'admin',
            resource: 'account',
            action: 'read'
        };
        expect(utils.getUnionAttrsOfRoles(grants, query)).toEqual([]);
        query.role = 'nonexisting';
        helper.expectACError(() => utils.getUnionAttrsOfRoles(grants, query));
    });

    test('#lockAC()', () => {
        expect(() => utils.lockAC(null)).toThrow();
        let ac = new AccessControl();
        helper.expectACError(() => utils.lockAC(ac));
        (ac as any)._grants = null;
        helper.expectACError(() => utils.lockAC(ac));
    });

});
