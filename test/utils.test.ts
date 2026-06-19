/**
 *  Test Suite: AccessControl
 *
 *  This suite mostly includes generic methods of the utils class. Most core
 *  methods (directly related with AccessControl) are tested via `ac.test.ts`.
 */

import { AccessControl } from '../src/index.js';
import type { IQueryInfo } from '../src/types/index.js';
import * as utils from '../src/utils/index.js';

// Reserved tokens that must never be accepted as a consumer name. Rejected by
// the name charset (see src/utils/constants).
const RESERVED_KEYWORDS = ['*', '!', '$', '$extend'];

// test helper
import { helper } from './helper.js';

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
    // @ts-expect-error
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
    expect(() => (o.x = 5)).toThrow();
    expect(() => ((o as any).inner = {})).toThrow();
    expect(() => (o.inner.x = 6)).toThrow();

    // v3 grants nest rule objects inside arrays — these must be frozen too,
    // otherwise lock() could be bypassed by mutating a rule in place.
    const grants = {
      admin: { video: { read: [{ possession: 'any', attributes: ['*'] }] } }
    };
    utils.deepFreeze(grants);
    const rule = grants.admin.video.read[0];
    expect(Object.isFrozen(grants.admin.video.read)).toBe(true);
    expect(Object.isFrozen(rule)).toBe(true);
    expect(() => ((rule as any).possession = 'own')).toThrow();
    expect(() => (rule.attributes as string[]).push('x')).toThrow();
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

    function Context(this) {
      this.ok = true;
    }

    utils.each(
      [1],
      function (this, item: number) {
        expect(this.ok).toBe(true);
      },
      new Context()
    );

    utils.eachKey(
      { key: 1 },
      function (this, key: string) {
        expect(this.ok).toBe(true);
      },
      new Context()
    );
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

  test('#normalizeName()', () => {
    expect(utils.normalizeName('admin')).toBe('admin');
    expect(utils.normalizeName('  admin  ')).toBe('admin'); // trims ends
    expect(utils.normalizeName('bulkExport')).toBe('bulkExport'); // case preserved
    expect(utils.normalizeName('post-docs')).toBe('post-docs'); // kebab-case ok
    expect(utils.normalizeName('my_role')).toBe('my_role'); // snake_case ok

    helper.expectACError(() => utils.normalizeName(''));
    helper.expectACError(() => (utils as any).normalizeName(1));
    helper.expectACError(() => (utils as any).normalizeName(null));
    helper.expectACError(() => utils.normalizeName('a b')); // internal space
    helper.expectACError(() => utils.normalizeName('post.docs')); // dot
    helper.expectACError(() => utils.normalizeName('a/b')); // group separator
    helper.expectACError(() => utils.normalizeName('a:b')); // possession separator
    helper.expectACError(() => utils.normalizeName('$extend')); // reserved
  });

  test('grants object validation (new shape, via #getInspectedGrants())', () => {
    const ok = (g: any) => expect(() => utils.getInspectedGrants(g)).not.toThrow();
    const bad = (g: any) => helper.expectACError(() => utils.getInspectedGrants(g));

    // valid: action → IGrant[]; possession optional (defaults to 'any')
    ok({ admin: { account: { read: [{ attributes: ['*'] }] } } });
    ok({ admin: { account: { read: [{ possession: 'own', attributes: ['*', '!id'] }] } } });
    // valid: $extend an existing role
    ok({ user: { account: { read: [{ attributes: ['*'] }] } }, admin: { $extend: ['user'] } });
    // valid: an explicit deny rule (effect: 'deny')
    ok({ admin: { account: { read: [{ effect: 'deny', attributes: ['*'] }] } } });

    // valid: a custom (non-CRUD) action name (§6)
    ok({ admin: { account: { publish: [{ attributes: ['*'] }] } } });

    bad({ admin: { account: { read: ['nope'] } } }); // a rule must be an object
    bad({ admin: { account: { 'bad action': [{ attributes: ['*'] }] } } }); // invalid action name (space)
    bad({ admin: { account: ['*'] } }); // resource must be an action→rules map
    bad({ admin: { account: { read: { attributes: ['*'] } } } }); // rules must be an array
    bad({ admin: { account: { read: [{ attributes: [''] }] } } }); // invalid attributes
    bad({ admin: { account: { read: [{ possession: 'all', attributes: ['*'] }] } } }); // bad possession
    bad({ admin: { account: { read: [{ effect: 'nope', attributes: ['*'] }] } } }); // bad effect
    bad({ admin: { $: { read: [{ attributes: ['*'] }] } } }); // reserved resource name
    bad({ admin: { $extend: ['ghost'] } }); // inherit non-existent role
    bad({ admin: ['*'] }); // role definition must be an object
  });

  test('#normalizeQueryInfo(), #normalizeAccessInfo()', () => {
    // @ts-expect-error (testing invalid input)
    helper.expectACError(() => utils.normalizeQueryInfo(null));
    // @ts-expect-error (testing invalid input)
    helper.expectACError(() => utils.normalizeQueryInfo({ role: null }));
    helper.expectACError(() => (utils as any).normalizeQueryInfo({ role: 1 }));
    helper.expectACError(() => utils.normalizeQueryInfo({ role: [] }));
    helper.expectACError(() => utils.normalizeQueryInfo({ role: '' }));
    helper.expectACError(() => utils.normalizeQueryInfo({ role: 'sa', resource: '' }));
    helper.expectACError(() => (utils as any).normalizeQueryInfo({ role: 'sa', resource: null }));
    helper.expectACError(() => (utils as any).normalizeQueryInfo({ role: 'sa', resource: [] }));

    // @ts-expect-error (testing invalid input)
    helper.expectACError(() => utils.normalizeAccessInfo(null));
    // @ts-expect-error (testing invalid input)
    helper.expectACError(() => utils.normalizeAccessInfo({ role: null }));
    helper.expectACError(() => utils.normalizeAccessInfo({ role: [] }));
    helper.expectACError(() => utils.normalizeAccessInfo({ role: '' }));
    helper.expectACError(() => (utils as any).normalizeAccessInfo({ role: 1 }));
    helper.expectACError(() => utils.normalizeAccessInfo({ role: 'sa', resource: '' }));
    helper.expectACError(() => (utils as any).normalizeAccessInfo({ role: 'sa', resource: null }));
    helper.expectACError(() => (utils as any).normalizeAccessInfo({ role: 'sa', resource: [] }));
  });

  test('#getRoleHierarchyOf()', () => {
    const grants: any = {
      admin: {
        $extend: ['user']
        // 'account': { 'read:any': ['*'] }
      }
    };
    helper.expectACError(() => utils.getRoleHierarchyOf(grants, 'admin'));
    grants.admin = { $extend: ['admin'] };
    helper.expectACError(() => utils.getRoleHierarchyOf(grants, 'admin'));

    grants.admin = { account: { 'read:any': ['*'] } };
    // @ts-expect-error (testing invalid input)
    helper.expectACError(() => utils.getRoleHierarchyOf(grants, null));
    helper.expectACError(() => utils.getRoleHierarchyOf(grants, ''));
  });

  test('#getNonExistentRoles()', () => {
    const grants: any = {
      admin: {
        account: { 'read:any': ['*'] }
      }
    };
    expect(utils.getNonExistentRoles(grants, [])).toEqual([]);
    expect(utils.getNonExistentRoles(grants, [''])).toEqual(['']);
  });

  test('#getCrossExtendingRole()', () => {
    const grants: any = {
      user: {},
      admin: {
        $extend: ['user', 'editor']
      },
      editor: {
        $extend: ['admin']
      }
    };
    expect(utils.getCrossExtendingRole(grants, 'admin', ['admin'])).toEqual(null);
    expect(utils.getCrossExtendingRole(grants, 'admin', ['user'])).toEqual(null);
    helper.expectACError(() => utils.getCrossExtendingRole(grants, 'user', ['admin']));
  });

  test('#extendRole()', () => {
    const grants: any = {
      user: {},
      admin: {
        $extend: ['user', 'editor']
      },
      editor: {
        $extend: ['admin']
      },
      viewer: {}
    };
    // @ts-expect-error (testing invalid input)
    helper.expectACError(() => utils.extendRole(grants, null, ['admin']));
    // @ts-expect-error (testing invalid input)
    helper.expectACError(() => utils.extendRole(grants, 'admin', null));
    helper.expectACError(() => utils.extendRole(grants, 'nonexisting', 'user'));
    helper.expectACError(() => utils.extendRole(grants, 'admin', 'nonexisting'));
    helper.expectACError(() => utils.extendRole(grants, 'admin', 'editor')); // cross
    helper.expectACError(() => utils.extendRole(grants, '$', 'user')); // reserved keyword
    expect(() => utils.extendRole(grants, 'admin', 'viewer')).not.toThrow();
  });

  test('#resolveAccess()', () => {
    const grants: any = {
      user: {
        account: {
          'read:own': ['*']
        }
      },
      admin: {
        $extend: ['user']
      }
    };
    const query: IQueryInfo = {
      role: 'admin',
      resource: 'account',
      action: 'read'
    };
    expect(utils.resolveAccess(grants, query).attributes).toEqual([]);
    query.role = 'nonexisting';
    helper.expectACError(() => utils.resolveAccess(grants, query));
  });

  test('#lockAC()', () => {
    // @ts-expect-error (testing invalid input)
    expect(() => utils.lockAC(null)).toThrow();
    const ac = new AccessControl();
    helper.expectACError(() => utils.lockAC(ac));
    (ac as any)._grants = null;
    helper.expectACError(() => utils.lockAC(ac));
  });
});
