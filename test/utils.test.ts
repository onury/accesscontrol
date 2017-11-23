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
        expect(utils.toStringArray(1)).toEqual(null);
        expect(utils.toStringArray(true)).toEqual(null);
        expect(utils.toStringArray(false)).toEqual(null);
        expect(utils.toStringArray(null)).toEqual(null);
        expect(utils.toStringArray(undefined)).toEqual(null);
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
    });

});

describe('Test Suite: utils (core)', () => {

    test('#validName(), #hasValidNames()', () => {
        let valid: any = 'someName';
        expect(utils.validName(valid)).toBe(true);
        expect(utils.validName(valid, false)).toBe(true);
        expect(utils.validName(valid, false, '')).toBe(true);

        let invalid: any = RESERVED_KEYWORDS[0];
        const msg = 'test message';
        expect(() => utils.validName(invalid)).toThrow();
        expect(() => utils.validName(invalid, true, msg)).toThrow(msg);
        expect(utils.validName(invalid, false)).toBe(false);

        valid = ['valid', 'name'];
        expect(utils.hasValidNames(valid)).toBe(true);
        expect(utils.hasValidNames(valid, false)).toBe(true);
        expect(utils.hasValidNames(valid, false, '')).toBe(true);

        invalid = ['valid', RESERVED_KEYWORDS[RESERVED_KEYWORDS.length - 1]];
        expect(() => utils.hasValidNames(invalid)).toThrow();
        expect(() => utils.hasValidNames(invalid, true, msg)).toThrow(msg);
        expect(utils.hasValidNames(invalid, false)).toBe(false);
    });

    test('#validResourceObject()', () => {
        expect(() => utils.validResourceObject(null)).toThrow();
        expect(() => utils.validResourceObject(null)).toThrow();
        expect(utils.validResourceObject({ 'create': [] })).toBe(true);
        expect(utils.validResourceObject({ 'create:any': ['*', '!id'] })).toBe(true);
        expect(utils.validResourceObject({ 'update:own': ['*'] })).toBe(true);

        expect(() => utils.validResourceObject({ 'invalid': [], 'create': [] })).toThrow();
        expect(() => utils.validResourceObject({ 'invalid:any': [] })).toThrow();
        expect(() => utils.validResourceObject({ 'read:own': ['*'], 'invalid:own': [] })).toThrow();

        expect(() => utils.validResourceObject({ 'create:all': [] })).toThrow();
        expect(() => utils.validResourceObject({ 'create:all': [] })).toThrow();

        expect(() => utils.validResourceObject({ 'create': null })).toThrow();
        expect(() => utils.validResourceObject({ 'create:own': undefined })).toThrow();
        expect(() => utils.validResourceObject({ 'read:own': [], 'create:any': [''] })).toThrow();
        expect(() => utils.validResourceObject({ 'create:any': ['*', ''] })).toThrow();
    });

    test('#validRoleObject()', () => {
        let grants: any = { 'admin': { 'account': { 'read:any': ['*'] } } };
        expect(utils.validRoleObject(grants, 'admin')).toBe(true);
        grants.admin = { 'account': ['*'] };
        expect(() => utils.validRoleObject(grants, 'admin')).toThrow();
        grants.admin = { 'account': { 'read:all': ['*'] } };
        expect(() => utils.validRoleObject(grants, 'admin')).toThrow();
    });

});
