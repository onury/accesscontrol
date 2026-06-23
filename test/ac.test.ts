/**
 *  Test Suite: AccessControl
 */

import { AccessControlError } from '../src/core/index.js';
import { Action, Possession } from '../src/enums/index.js';
import { AccessControl } from '../src/index.js';
import type {
  IAccessInfo,
  IGrants,
  IGrantsList,
  IQueryInfo,
  IResourceGrants,
  UnknownObject
} from '../src/types/index.js';
import * as utils from '../src/utils/index.js';

// Reserved tokens that must never be accepted as a consumer name (role,
// resource or action). Rejected by the name charset (see src/utils/constants).
const RESERVED_KEYWORDS = ['*', '!', '$', '$extend'];

// test helper
import { helper } from './helper.js';

describe('Test Suite: AccessControl', () => {
  // grant list fetched from DB (to be converted to a valid grants object)
  const grantList: IGrantsList = [
    { role: 'admin', resource: 'video', action: 'create:any', attributes: ['*'] },
    { role: 'admin', resource: 'video', action: 'read:any', attributes: ['*'] },
    { role: 'admin', resource: 'video', action: 'update:any', attributes: ['*'] },
    { role: 'admin', resource: 'video', action: 'delete:any', attributes: ['*'] },

    { role: 'user', resource: 'video', action: 'create:own', attributes: '*, !id' }, // comma-separated attrs
    { role: 'user', resource: 'video', action: 'read:any', attributes: '*; !id' }, // semi-colon separated attrs
    { role: 'user', resource: 'video', action: 'update:own', attributes: ['*', '!id'] }, // Array attrs
    { role: 'user', resource: 'video', action: 'delete:own', attributes: ['*'] }
  ];

  // valid grants object (v3 shape: action → IGrant[]; possession is a field)
  const grantsObject: IGrants = {
    admin: {
      video: {
        create: [{ possession: 'any', attributes: ['*'] }],
        read: [{ possession: 'any', attributes: ['*'] }],
        update: [{ possession: 'any', attributes: ['*'] }],
        delete: [{ possession: 'any', attributes: ['*'] }]
      }
    },
    user: {
      video: {
        create: [{ possession: 'own', attributes: ['*'] }],
        read: [{ possession: 'own', attributes: ['*'] }],
        update: [{ possession: 'own', attributes: ['*'] }],
        delete: [{ possession: 'own', attributes: ['*'] }]
      }
    }
  };

  // reads the attributes of the first stored grant rule matching action(+possession)
  function ruleAttrs(
    ac: AccessControl,
    role: string,
    resource: string,
    action: string,
    possession: 'own' | 'any' = 'any'
  ): string[] | undefined {
    const res = ac.getGrants()[role]?.[resource] as
      | Record<string, Array<{ possession?: string; attributes: string[]; effect?: string }>>
      | undefined;
    const rules = res?.[action] ?? [];
    const m = rules.find((r) => (r.possession ?? 'any') === possession && r.effect !== 'deny');
    return m?.attributes;
  }

  // let ac;
  // beforeEach (() => {
  //     ac = new AccessControl();
  // });

  // ---------------------------
  //  TESTS
  // ---------------------------

  test('throw on invalid grants object', () => {
    const ac = new AccessControl();

    // `undefined` is handled by the constructor's default value (see below)
    let invalid: unknown[] = [null, true, false, '', NaN, new Date(), () => {}];
    invalid.forEach((o) => {
      // @ts-expect-error
      helper.expectACError(() => new AccessControl(o));
      // @ts-expect-error
      helper.expectACError(() => ac.setGrants(o));
    });

    // omitting is allowed (results in empty grants object: {})
    expect(() => new AccessControl()).not.toThrow();
    // empty object is allowed
    expect(() => new AccessControl({})).not.toThrow();
    expect(new AccessControl({}).getGrants()).toEqual({});
    // explicit `undefined` to the constructor falls back to the default ({}) and
    // does not throw; but passing it directly to setGrants() is not allowed.
    expect(() => new AccessControl(undefined)).not.toThrow();
    // @ts-expect-error
    helper.expectACError(() => ac.setGrants(undefined));

    // Initial Grants as an Object
    // ----------------------------

    // reserved keywords
    helper.expectACError(() => ac.setGrants({ $: {} }));
    helper.expectACError(() => ac.setGrants({ $extend: {} }));
    // if $extend is set to an array of strings or empty array, it's valid
    // (contains inherited roles)
    expect(() => ac.setGrants({ admin: { $extend: [] } })).not.toThrow();
    // empty string in the $extend array is not allowed
    helper.expectACError(() => ac.setGrants({ admin: { $extend: [''] } }));

    // role definition must be an object
    invalid = [[], undefined, null, true, new Date()];
    invalid.forEach((o) => {
      // @ts-expect-error
      helper.expectACError(() => ac.setGrants({ role: invalid }));
    });
    // resource definition must be an object
    invalid.forEach((o) => {
      // @ts-expect-error
      helper.expectACError(() => ac.setGrants({ role: { resource: invalid } }));
    });
    // §6: actions are any valid *name* (not just CRUD). The action key must be a
    // bare name — possession lives in the rule — so a name with reserved/invalid
    // chars still throws.
    helper.expectACError(() => ac.setGrants({ role: { resource: { 'remove:any': [] } } })); // ':'
    helper.expectACError(() => ac.setGrants({ role: { resource: { 'bad action': [] } } })); // space
    // custom (non-CRUD) action names are accepted
    expect(() =>
      ac.setGrants({ role: { resource: { publish: [{ attributes: ['*'] }] } } })
    ).not.toThrow();
    expect(() =>
      ac.setGrants({ role: { resource: { createany: [{ attributes: ['*'] }] } } })
    ).not.toThrow();
    // action/possession is ok but value is invalid
    invalid = [undefined, null, true, new Date(), {}];
    invalid.forEach((o) => {
      // @ts-expect-error
      helper.expectACError(() => ac.setGrants({ role: { resource: { 'create:any': invalid } } }));
    });

    // Initial Grants as an Array
    // ----------------------------

    // empty array is allowed. a flat list will be converted to inner grants
    // object. empty array results in {}.
    expect(() => new AccessControl([])).not.toThrow();
    expect(new AccessControl([]).getGrants()).toEqual({});
    // array should be an array of objects
    // @ts-expect-error
    helper.expectACError(() => ac.setGrants([[]]));
    // no empty grant items
    // @ts-expect-error
    helper.expectACError(() => ac.setGrants([{}]));
    // e.g. $extend is not allowed for role or resource names. it's a reserved keyword.
    RESERVED_KEYWORDS.forEach((name) => {
      helper.expectACError(() =>
        ac.setGrants([{ role: name, resource: 'video', action: 'create:any' }])
      );
      helper.expectACError(() =>
        ac.setGrants([{ role: 'admin', resource: name, action: 'create:any' }])
      );
      helper.expectACError(() =>
        ac.setGrants([{ role: 'admin', resource: 'video', action: name }])
      );
    });

    // attributes property can be omitted
    expect(() =>
      ac.setGrants([{ role: 'admin', resource: 'video', action: 'create:any' }])
    ).not.toThrow();
    // role, resource or action properties cannot be omitted (validated at runtime;
    // only the missing-`role` shape is additionally rejected by the types)
    // @ts-expect-error - missing `role`
    helper.expectACError(() => ac.setGrants([{ resource: 'video', action: 'create:any' }]));
    helper.expectACError(() => ac.setGrants([{ role: 'admin', resource: 'video' }]));
    helper.expectACError(() => ac.setGrants([{ role: 'admin', action: 'create:any' }]));

    // gh #109 — a flat list straight from a datastore (e.g. Mongoose `.lean()`
    // docs) carries extra non-grant keys like `_id`/`__v`. These surplus
    // properties must be ignored, not rejected.
    expect(() =>
      ac.setGrants([
        {
          _id: 'a1',
          __v: 0,
          role: 'admin',
          resource: 'video',
          action: 'create:any',
          attributes: ['*']
        },
        {
          _id: 'a2',
          __v: 0,
          role: 'admin',
          resource: 'video',
          action: 'read:any',
          attributes: ['*']
        }
      ] as unknown as IGrantsList)
    ).not.toThrow();
    expect(ac.can('admin').createAny('video').granted).toBe(true);
    expect(ac.can('admin').readAny('video').granted).toBe(true);
  });

  test('construct with grants array or object, output a grants object', () => {
    let ac = new AccessControl(grantList);
    let grants = ac.getGrants();
    expect(utils.type(grants)).toEqual('object');
    expect(utils.type(grants.admin)).toEqual('object');
    expect((grants.admin.video as IResourceGrants).create).toEqual(expect.any(Array));
    // console.log(grants);

    ac = new AccessControl(grantsObject);
    grants = ac.getGrants();
    expect(utils.type(grants)).toEqual('object');
    expect(utils.type(grants.admin)).toEqual('object');
    expect((grants.admin.video as IResourceGrants).create).toEqual(expect.any(Array));

    grants = {
      user: {
        account: {
          read: [{ possession: 'own', attributes: ['*'] }]
        }
      },
      admin: {
        $extend: ['user']
      }
    };
    ac = new AccessControl(grants);
    expect(utils.type(grants)).toEqual('object');
    expect(ac.can('user').readOwn('account').granted).toBe(true);
    expect(ac.can('user').readOwn('account').attributes).toEqual(['*']);
    expect(ac.can('admin').readOwn('account').granted).toBe(true);
    expect(ac.can('admin').readOwn('account').attributes).toEqual(['*']);
  });

  // gh #108 — a role defined only via `$extend` (no own grants) must resolve
  // regardless of declaration order. The two-pass object parser materializes
  // every role key before applying inheritance, so the extended base may appear
  // before or after the extender.
  test('object grants: role defined only via $extend resolves in any order (#108)', () => {
    const base: IGrants = {
      base_member: { user: { read: [{ possession: 'own', attributes: ['*'] }] } }
    };
    const paid: IGrants = { paid_member: { $extend: ['base_member'] } };

    // base declared BEFORE extender
    let ac = new AccessControl({ ...base, ...paid });
    expect(ac.can('paid_member').readOwn('user').granted).toBe(true);

    // base declared AFTER extender (the exact #108 shape)
    ac = new AccessControl({ ...paid, ...base });
    expect(ac.can('paid_member').readOwn('user').granted).toBe(true);

    // a genuinely non-existent base still throws (distinct from #108)
    helper.expectACError(() => new AccessControl({ paid_member: { $extend: ['ghost'] } }));
  });

  test('reset grants with #reset() only', () => {
    const ac = new AccessControl(grantsObject);
    expect(ac.getRoles().length).toBeGreaterThan(0); // make sure not empty
    helper.expectACError(() => (ac as any).setGrants());
    // @ts-expect-error
    helper.expectACError(() => ac.setGrants(null));
    // @ts-expect-error
    helper.expectACError(() => ac.setGrants(undefined));
    expect(ac.reset().getGrants()).toEqual({});
    expect(ac.setGrants({}).getGrants()).toEqual({});
  });

  test('add grants from flat list (db), check/remove roles and resources', () => {
    const ac = new AccessControl();

    expect((ac as any).hasRole()).toEqual(false);
    // @ts-expect-error
    expect(ac.hasRole(null)).toEqual(false);
    // @ts-expect-error
    expect(ac.hasRole(undefined)).toEqual(false);
    expect(ac.hasRole('')).toEqual(false);

    expect((ac as any).hasResource()).toEqual(false);
    // @ts-expect-error
    expect(ac.hasResource(null)).toEqual(false);
    // @ts-expect-error
    expect(ac.hasResource(undefined)).toEqual(false);
    expect(ac.hasResource('')).toEqual(false);

    ac.setGrants(grantList.concat());
    // console.log('grants', ac.getGrants());
    // console.log('resources', ac.getResources());
    // console.log('roles', ac.getRoles());

    // comma/semi-colon separated should be turned into string arrays
    const attrs1 = ac.can('user').createOwn('video').attributes;
    const attrs2 = ac.can('user').readAny('video').attributes;
    const attrs3 = ac.can('user').updateOwn('video').attributes; // `query` » alias of `can`
    // console.log(attrs1);
    expect(attrs1.length).toEqual(2);
    expect(attrs2.length).toEqual(2);
    expect(attrs3.length).toEqual(2);

    // check roles & resources
    expect(ac.getRoles().length).toEqual(2);
    expect(ac.getResources().length).toEqual(1);
    expect(ac.hasRole('admin')).toEqual(true);
    expect(ac.hasRole('user')).toEqual(true);
    expect(ac.hasRole(['user', 'admin'])).toEqual(true);
    expect(ac.hasRole(['user', 'moderator'])).toEqual(false);
    expect(ac.hasRole('moderator')).toEqual(false);
    expect(ac.hasResource('video')).toEqual(true);
    expect(ac.hasResource(['video', 'photo'])).toEqual(false);
    ac.grant('admin').create('image');
    expect(ac.hasResource(['video', 'image'])).toEqual(true);

    // removeRoles should also accept a string
    ac.removeRoles('admin');
    expect(ac.hasRole('admin')).toEqual(false);
    // throw on nonexisting role
    helper.expectACError(() => ac.removeRoles([]));
    helper.expectACError(() => ac.removeRoles(['']));
    helper.expectACError(() => ac.removeRoles(['none']));
    // no role named moderator
    helper.expectACError(() => ac.removeRoles(['user', 'moderator']));
    expect(ac.getRoles().length).toEqual(0);
    // removeRoles should accept a string or array
    ac.removeResources(['video']);
    expect(ac.getResources().length).toEqual(0);
    expect(ac.hasResource('video')).toEqual(false);
  });

  test('#removeResources(), #_removePermission()', () => {
    const ac = new AccessControl();
    function grantAll() {
      ac.grant(['user', 'admin']).create('photo').createOwn('photo');
      expect(ac.can('admin').createAny('photo').granted).toEqual(true);
      expect(ac.can('user').createAny('photo').granted).toEqual(true);
      expect(ac.can('admin').createOwn('photo').granted).toEqual(true);
      expect(ac.can('user').createOwn('photo').granted).toEqual(true);
    }

    grantAll();
    // removeResources() is like an alias without the third argument of _removePermission().
    (ac as any).removeResources('photo', 'user');
    expect(ac.can('admin').createAny('photo').granted).toEqual(true);
    expect(ac.can('user').createAny('photo').granted).toEqual(false);
    expect(ac.can('user').createOwn('photo').granted).toEqual(false);
    expect(ac.getGrants().user.photo).toBeUndefined();

    helper.expectACError(() => (ac as any)._removePermission(null));
    helper.expectACError(() => (ac as any)._removePermission(''));
    helper.expectACError(() => (ac as any)._removePermission([]));
    helper.expectACError(() => (ac as any)._removePermission(['']));

    grantAll();
    helper.expectACError(() => (ac as any)._removePermission('photo', ''));
    helper.expectACError(() => (ac as any)._removePermission(['photo'], null));
    helper.expectACError(() => (ac as any)._removePermission('photo', []));
    helper.expectACError(() => (ac as any)._removePermission('photo', ['']));

    // removing a resource for a specific role drops the whole resource node
    grantAll();
    (ac as any)._removePermission('photo', 'user');
    expect(ac.can('admin').createAny('photo').granted).toEqual(true);
    expect(ac.can('user').createAny('photo').granted).toEqual(false);
    expect(ac.getGrants().user.photo).toBeUndefined();
  });

  test('grant/deny access and check permissions', () => {
    const ac = new AccessControl(),
      attrs = ['*', '!size'];

    ac.grant('user').createAny('photo', attrs);
    expect(ruleAttrs(ac, 'user', 'photo', 'create', 'any')).toEqual(attrs);
    expect(ac.can('user').createAny('photo').attributes).toEqual(attrs);

    ac.deny('user').createAny('photo'); // deny all (deny-overrides, §5.6)
    expect(ac.can('user').createAny('photo').granted).toEqual(false);
    expect(ac.can('user').createAny('photo').attributes).toEqual([]);

    ac.grant('user').createOwn('photo', attrs);
    // console.log('ac.getGrants()', ac.getGrants());
    expect(ruleAttrs(ac, 'user', 'photo', 'create', 'own')).toEqual(attrs);
    expect(ac.can('user').createOwn('photo').attributes).toEqual(attrs);

    // grant multiple roles the same permission for the same resource
    ac.grant(['user', 'admin']).readAny('photo', attrs);
    expect(ac.can('user').readAny('photo').granted).toEqual(true);
    expect(ac.can('admin').readAny('photo').granted).toEqual(true);
    // deny multiple roles (comma-separated) the same permission for the same resource
    ac.deny('user, admin').readAny('photo');
    expect(ac.can('user').readAny('photo').granted).toEqual(false);
    expect(ac.can('admin').readAny('photo').granted).toEqual(false);

    ac.grant('user').updateAny('photo', attrs);
    expect(ruleAttrs(ac, 'user', 'photo', 'update', 'any')).toEqual(attrs);
    expect(ac.can('user').updateAny('photo').attributes).toEqual(attrs);

    ac.grant('user').updateOwn('photo', attrs);
    expect(ruleAttrs(ac, 'user', 'photo', 'update', 'own')).toEqual(attrs);
    expect(ac.can('user').updateOwn('photo').attributes).toEqual(attrs);

    ac.grant('user').deleteAny('photo', attrs);
    expect(ruleAttrs(ac, 'user', 'photo', 'delete', 'any')).toEqual(attrs);
    expect(ac.can('user').deleteAny('photo').attributes).toEqual(attrs);

    ac.grant('user').deleteOwn('photo', attrs);
    expect(ruleAttrs(ac, 'user', 'photo', 'delete', 'own')).toEqual(attrs);
    expect(ac.can('user').deleteOwn('photo').attributes).toEqual(attrs);

    // `query` » alias of `can`
    expect(ac.can('user').updateAny('photo').attributes).toEqual(attrs);
    expect(ac.can('user').deleteAny('photo').attributes).toEqual(attrs);
    expect(ac.can('user').deleteOwn('photo').attributes).toEqual(attrs);
  });

  test('explicit undefined', () => {
    const ac = new AccessControl();
    helper.expectACError(() => (ac as any).grant(undefined));
    helper.expectACError(() => (ac as any).deny(undefined));
    helper.expectACError(() => (ac as any).can(undefined));
  });

  test('aliases: #allow(), #reject(), #query()', () => {
    const ac = new AccessControl();

    ac.grant(['user', 'admin']).createAny('photo');
    expect(ac.can('user').createAny('photo').granted).toBe(true);

    ac.reset();
    // allow » alias of grant
    ac.grant(['user', 'admin']).createAny('photo');
    // query » alias of can
    expect(ac.can('user').createAny('photo').granted).toBe(true);

    // reject » alias of deny
    ac.deny('user').createAny('photo');
    expect(ac.can('user').createAny('photo').granted).toBe(false);
    expect(ac.can('user').createAny('photo').granted).toBe(false);
  });

  test('#check()', () => {
    const ac = new AccessControl(grantsObject);
    expect(ac.can('admin').createAny('video').granted).toBe(true);

    const queryInfo: IQueryInfo = {
      role: 'admin',
      resource: 'video',
      action: 'create:any'
    };
    expect(ac.check(queryInfo).granted).toBe(true);
    queryInfo.role = 'user';
    expect(ac.check(queryInfo).granted).toBe(false);
    queryInfo.action = 'create:own';
    expect(ac.check(queryInfo).granted).toBe(true);
  });

  test('chain grant methods and check permissions', () => {
    const ac = new AccessControl(),
      attrs = ['*'];

    ac.grant('superadmin')
      .createAny('profile', attrs)
      .readAny('profile', attrs)
      .createAny('video', []) // no attributes allowed
      .createAny('photo'); // all attributes allowed

    expect(ac.can('superadmin').createAny('profile').granted).toEqual(true);
    expect(ac.can('superadmin').readAny('profile').granted).toEqual(true);
    expect(ac.can('superadmin').createAny('video').granted).toEqual(false);
    expect(ac.can('superadmin').createAny('photo').granted).toEqual(true);
  });

  test('grant/deny access via object and check permissions', () => {
    const ac = new AccessControl();

    const o1: IAccessInfo = {
      role: 'moderator',
      resource: 'post',
      action: 'create:any', // action:possession
      attributes: ['*'] // grant only
    };
    const o2: IAccessInfo = {
      role: 'moderator',
      resource: 'news',
      action: 'read', // separate action
      possession: Possession.OWN, // separate possession
      attributes: ['*'] // grant only
    };
    const o3: IAccessInfo = {
      role: 'moderator',
      resource: 'book',
      // no action/possession set
      attributes: ['*'] // grant only
    };

    ac.grant(o1).grant(o2);
    ac.grant(o3).updateAny();

    expect(ac.can('moderator').createAny('post').granted).toEqual(true);
    expect(ac.can('moderator').readOwn('news').granted).toEqual(true);
    expect(ac.can('moderator').updateAny('book').granted).toEqual(true);

    ac.deny(o1).deny(o2);
    ac.deny(o3).updateAny();

    expect(ac.can('moderator').createAny('post').granted).toEqual(false);
    expect(ac.can('moderator').readOwn('news').granted).toEqual(false);
    expect(ac.can('moderator').updateAny('book').granted).toEqual(false);

    // should overwrite already defined action/possession in o1 object
    ac.grant(o1).readOwn();
    expect(ac.can('moderator').readOwn('post').granted).toEqual(true);
    ac.deny(o1).readOwn();
    expect(ac.can('moderator').readOwn('post').granted).toEqual(false);

    // non-set action (update:own)
    expect(ac.can('moderator').updateOwn('news').granted).toEqual(false);
    // non-existent resource
    expect(ac.can('moderator').createAny('foo').granted).toEqual(false);
  });

  test('grant/deny access (variation, chained)', () => {
    const ac = new AccessControl();
    ac.setGrants(grantsObject);

    expect(ac.can('admin').createAny('video').granted).toEqual(true);
    ac.deny('admin').create('video');
    expect(ac.can('admin').createAny('video').granted).toEqual(false);

    ac.grant('foo').createOwn('bar');
    expect(ac.can('foo').createAny('bar').granted).toEqual(false);
    expect(ac.can('foo').createOwn('bar').granted).toEqual(true);

    ac.grant('foo').create('baz', []); // no attributes, actually denied instead of granted
    expect(ac.can('foo').create('baz').granted).toEqual(false);

    ac.grant('qux')
      .createOwn('resource1')
      .updateOwn('resource2')
      .readAny('resource1')
      .deleteAny('resource1', []);
    expect(ac.can('qux').createOwn('resource1').granted).toEqual(true);
    expect(ac.can('qux').updateOwn('resource2').granted).toEqual(true);
    expect(ac.can('qux').readAny('resource1').granted).toEqual(true);
    expect(ac.can('qux').deleteAny('resource1').granted).toEqual(false);

    ac.deny('qux')
      .createOwn('resource1')
      .updateOwn('resource2')
      .readAny('resource1')
      .deleteAny('resource1', []);
    expect(ac.can('qux').createOwn('resource1').granted).toEqual(false);
    expect(ac.can('qux').updateOwn('resource2').granted).toEqual(false);
    expect(ac.can('qux').readAny('resource1').granted).toEqual(false);
    expect(ac.can('qux').deleteAny('resource1').granted).toEqual(false);

    ac.grant('editor').resource('file1').updateAny();
    ac.grant().role('editor').updateAny('file2');
    ac.grant().role('editor').resource('file3').updateAny();
    expect(ac.can('editor').updateAny('file1').granted).toEqual(true);
    expect(ac.can('editor').updateAny('file2').granted).toEqual(true);
    expect(ac.can('editor').updateAny('file3').granted).toEqual(true);

    ac.deny('editor').resource('file1').updateAny();
    ac.deny().role('editor').updateAny('file2');
    ac.deny().role('editor').resource('file3').updateAny();
    expect(ac.can('editor').updateAny('file1').granted).toEqual(false);
    expect(ac.can('editor').updateAny('file2').granted).toEqual(false);
    expect(ac.can('editor').updateAny('file3').granted).toEqual(false);

    ac.grant('editor')
      .resource('fileX')
      .readAny()
      .createOwn()
      .resource('fileY')
      .updateOwn()
      .deleteOwn();
    expect(ac.can('editor').readAny('fileX').granted).toEqual(true);
    expect(ac.can('editor').createOwn('fileX').granted).toEqual(true);
    expect(ac.can('editor').updateOwn('fileY').granted).toEqual(true);
    expect(ac.can('editor').deleteOwn('fileY').granted).toEqual(true);

    ac.deny('editor')
      .resource('fileX')
      .readAny()
      .createOwn()
      .resource('fileY')
      .updateOwn()
      .deleteOwn();
    expect(ac.can('editor').readAny('fileX').granted).toEqual(false);
    expect(ac.can('editor').createOwn('fileX').granted).toEqual(false);
    expect(ac.can('editor').updateOwn('fileY').granted).toEqual(false);
    expect(ac.can('editor').deleteOwn('fileY').granted).toEqual(false);
  });

  test('switch-chain grant/deny roles', () => {
    const ac = new AccessControl();
    ac.grant('r1')
      .createOwn('a')
      .grant('r2')
      .createOwn('b')
      .readAny('b')
      .deny('r1')
      .deleteAny('b')
      .grant('r1')
      .updateAny('c')
      .deny('r2')
      .readAny('c');

    expect(ac.can('r1').createOwn('a').granted).toEqual(true);
    expect(ac.can('r1').deleteAny('b').granted).toEqual(false);
    expect(ac.can('r1').updateAny('c').granted).toEqual(true);
    expect(ac.can('r2').createOwn('b').granted).toEqual(true);
    expect(ac.can('r2').readAny('b').granted).toEqual(true);
    expect(ac.can('r2').readAny('c').granted).toEqual(false);
    // console.log(JSON.stringify(ac.getGrants(), null, '  '));
  });

  test('Access#deny() yields no effective attributes (deny-overrides)', () => {
    const ac = new AccessControl();
    ac.deny('user').createAny('book', ['*']);
    expect(ac.can('user').createAny('book').granted).toEqual(false);
    expect(ac.can('user').createAny('book').attributes).toEqual([]);
  });

  test('grant comma/semi-colon separated roles', () => {
    const ac = new AccessControl();
    // also supporting comma/semi-colon separated roles
    ac.grant('role2; role3, editor; viewer, agent').createOwn('book');
    expect(ac.hasRole('role3')).toEqual(true);
    expect(ac.hasRole('editor')).toEqual(true);
    expect(ac.hasRole('agent')).toEqual(true);
  });

  test('Permission#roles, Permission#resource', () => {
    const ac = new AccessControl();
    // also supporting comma/semi-colon separated roles
    ac.grant('foo, bar').createOwn('baz');
    expect(ac.can('bar').createAny('baz').granted).toEqual(false);
    expect(ac.can('bar').createOwn('baz').granted).toEqual(true);
    // returned permission should provide queried role(s) as array
    expect(ac.can('foo').create('baz').roles).toContain('foo');
    // returned permission should provide queried resource
    expect(ac.can('foo').create('baz').resource).toEqual('baz');
    // create is createAny. but above only returns the queried value, not the result.
    // returned permission should provide the bare action checked
    expect(ac.can('foo').create('baz').action).toEqual('create');
  });

  test('Permission#action / #possession (resolved)', () => {
    const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
    ac.grant('admin').readAny('post', ['*']); // any
    ac.grant('user').readOwn('post', ['*']); // own only
    ac.grant('editor').action('publish:own', 'article', ['*']); // custom action

    // bare action name (possession suffix stripped), incl. custom actions
    expect(ac.can('admin').readAny('post').action).toEqual('read');
    expect(
      ac.can('editor', { user: { id: 1 }, article: { ownerId: 1 } }).do('publish:own', 'article')
        .action
    ).toEqual('publish');

    // possession resolves to what actually granted access (any ⊇ own)
    expect(ac.can('admin').readAny('post').possession).toEqual('any');
    const ownCtx = { user: { id: 1 }, post: { ownerId: 1 } };
    expect(ac.can('user', ownCtx).readOwn('post').possession).toEqual('own'); // granted by own rule
    expect(ac.can('admin', ownCtx).readOwn('post').possession).toEqual('any'); // own query, granted via any cascade

    // on denial, the requested possession is echoed back (own and any)
    const deniedOwn = ac.can('user', { user: { id: 1 }, post: { ownerId: 2 } }).readOwn('post');
    expect(deniedOwn.granted).toBe(false);
    expect(deniedOwn.possession).toEqual('own');
    const deniedAny = ac.can('user').readAny('post'); // user has readOwn only ⇒ denied
    expect(deniedAny.granted).toBe(false);
    expect(deniedAny.possession).toEqual('any');
  });

  test('#getActions(): all, per-role, and inherited', () => {
    const ac = new AccessControl();
    ac.grant('user').readOwn('profile');
    ac.grant('admin').extend('user').deleteAny('post').createAny('post');

    expect(ac.getActions().sort()).toEqual(['create', 'delete', 'read']); // all
    expect(ac.getActions('user')).toEqual(['read']); // scoped to one role
    expect(ac.getActions('admin').sort()).toEqual(['create', 'delete', 'read']); // own + inherited
    expect(ac.getActions(['user', 'admin']).sort()).toEqual(['create', 'delete', 'read']);
    helper.expectACError(() => ac.getActions('ghost')); // unknown role throws
  });

  test('#extendRole(), #removeRoles(), Access#extend()', () => {
    const ac = new AccessControl();

    ac.grant('admin').createOwn('book');

    // role "onur" is not found
    expect(() => ac.extendRole('onur', 'admin')).toThrow();
    ac.grant('onur').extend('admin');

    // @ts-expect-error
    expect(ac.getGrants().onur.$extend.length).toEqual(1);
    // @ts-expect-error
    expect(ac.getGrants().onur.$extend[0]).toEqual('admin');

    ac.grant('role2, role3, editor, viewer, agent').createOwn('book');

    ac.extendRole('onur', ['role2', 'role3']);
    expect(ac.getGrants().onur.$extend).toEqual(['admin', 'role2', 'role3']);

    ac.grant('admin').extend('editor');
    expect(ac.getGrants().admin.$extend).toEqual(['editor']);
    ac.grant('admin').extend(['viewer', 'editor', 'agent']).readAny('video');
    expect(ac.getGrants().admin.$extend).toContain('editor');
    expect(ac.getGrants().admin.$extend).toEqual(['editor', 'viewer', 'agent']);

    ac.grant(['editor', 'agent']).extend(['role2', 'role3']).updateOwn('photo');
    expect(ac.getGrants().editor.$extend).toEqual(['role2', 'role3']);
    expect(ac.getGrants().agent.$extend).toEqual(['role2', 'role3']);

    ac.removeRoles(['editor', 'agent']);
    expect(ac.getGrants().editor).toBeUndefined();
    expect(ac.getGrants().agent).toBeUndefined();
    expect(ac.getGrants().admin.$extend).not.toContain('editor');
    expect(ac.getGrants().admin.$extend).not.toContain('agent');

    expect(() => ac.grant('roleX').extend('roleX')).toThrow();
    expect(() => ac.grant(['admin2', 'roleX']).extend(['roleX', 'admin3'])).toThrow();

    // console.log(JSON.stringify(ac.getGrants(), null, '  '));
  });

  test('extend before or after resource permissions are granted', () => {
    const ac: AccessControl = new AccessControl();

    function init() {
      ac.reset().grant(['user', 'admin']);
      expect(ac.getRoles().length).toEqual(2);
    }

    // case #1
    init();
    ac.grant('admin')
      .extend('user') // assuming user role already exists
      .grant('user')
      .createOwn('video');
    expect(ac.can('admin').createOwn('video').granted).toEqual(true);

    // case #2
    init();
    ac.grant('user').createOwn('video').grant('admin').extend('user');
    expect(ac.can('admin').createOwn('video').granted).toEqual(true);
  });

  test('extend multi-level (deep) roles', () => {
    const ac = new AccessControl();
    ac.grant('viewer').readAny('devices');
    ac.grant('ops').extend('viewer').updateAny('devices', ['*', '!id']);
    ac.grant('admin').extend('ops').deleteAny('devices');
    ac.grant('superadmin').extend(['admin', 'ops']).createAny('devices');
    // just re-extending already extended roles. this should pass.
    expect(() => ac.extendRole(['ops', 'admin'], 'viewer')).not.toThrow();

    expect(ac.can('ops').readAny('devices').granted).toEqual(true);
    expect(ac.can('admin').readAny('devices').granted).toEqual(true);
    expect(ac.can('admin').updateAny('devices').granted).toEqual(true);
    expect(ac.can('superadmin').readAny('devices').granted).toEqual(true);

    expect(ac.can('superadmin').updateAny('devices').attributes).toEqual(['*', '!id']);
    ac.grant('superadmin').updateAny('devices', ['*']);
    expect(ac.can('superadmin').updateAny('devices').attributes).toEqual(['*']);

    expect(ac.getInheritedRolesOf('viewer')).toEqual([]);
    expect(ac.getInheritedRolesOf('ops')).toEqual(['viewer']);
    expect(ac.getInheritedRolesOf('admin')).toEqual(['ops', 'viewer']);
    expect(ac.getInheritedRolesOf('superadmin')).toEqual(['admin', 'ops', 'viewer']);

    // console.log(JSON.stringify(ac.getGrants(), null, '  '));
  });

  test('throw if target role or inherited role does not exit', () => {
    const ac = new AccessControl();
    helper.expectACError(() => ac.grant().createOwn());
    ac.setGrants(grantsObject);
    helper.expectACError(() => ac.can('invalid-role').createOwn('video'), 'Role not found');
    helper.expectACError(() => ac.grant('user').extend('invalid-role'));
    helper.expectACError(() => ac.grant('user').extend(['invalid1', 'invalid2']));
  });

  test('throw on invalid or reserved names', () => {
    const ac = new AccessControl();
    RESERVED_KEYWORDS.forEach((name) => {
      helper.expectACError(() => ac.grant(name));
      helper.expectACError(() => ac.deny(name));
      helper.expectACError(() => ac.grant().role(name));
      helper.expectACError(() => ac.grant('role').resource(name));
    });
    expect(() => ac.grant()).not.toThrow(); // omitted.
    helper.expectACError(() => ac.grant(undefined)); // explicit undefined
    // @ts-expect-error
    helper.expectACError(() => ac.grant(null));
    helper.expectACError(() => ac.grant(''));
    helper.expectACError(() => (ac as any).grant(1));
    helper.expectACError(() => (ac as any).grant(true));
    helper.expectACError(() => (ac as any).grant(false));
    helper.expectACError(() => (ac as any).grant([]));
    helper.expectACError(() => (ac as any).grant({}));
    // @ts-expect-error
    helper.expectACError(() => new AccessControl({ $: [] }));
    helper.expectACError(() => new AccessControl({ $extend: {} }));
  });

  test('negation-only attributes imply "*" (§3)', () => {
    const ac = new AccessControl();
    // builder form
    ac.grant('user').readAny('profile', ['!password']);
    expect(ac.can('user').readAny('profile').granted).toBe(true);
    expect(ac.can('user').readAny('profile').attributes).toEqual(['*', '!password']);
    // object form
    const ac2 = new AccessControl({
      user: { profile: { read: [{ possession: 'any', attributes: ['!password'] }] } }
    });
    expect(ac2.can('user').readAny('profile').attributes).toEqual(['*', '!password']);
  });

  test('grantsList (flat/DB form) supports $extend via inheritance rows', () => {
    const list = [
      { role: 'user', resource: 'video', action: 'read:any', attributes: ['*'] },
      { role: 'admin', resource: 'video', action: 'delete:any', attributes: ['*'] },
      { role: 'admin', $extend: ['user'] }
    ];
    const ac = new AccessControl(list);
    // admin inherits user's read via the extend row
    expect(ac.can('admin').readAny('video').granted).toBe(true);
    expect(ac.can('admin').deleteAny('video').granted).toBe(true);
    expect(ac.getInheritedRolesOf('admin')).toEqual(['user']);
  });

  test('init with grants object with $extend (issue #22)', () => {
    // tslint:disable
    const grants: IGrants = {
      viewer: {
        account: {
          read: [{ possession: 'own', attributes: ['*'] }]
        }
      },
      user: {
        $extend: ['viewer'],
        account: {
          update: [{ possession: 'own', attributes: ['*'] }]
        }
      },
      admin: {
        $extend: ['user'],
        account: {
          create: [{ possession: 'any', attributes: ['*'] }],
          delete: [{ possession: 'any', attributes: ['*'] }]
        }
      }
    };
    // tslint:enable
    expect(() => new AccessControl(grants)).not.toThrow();
    const ac = new AccessControl();
    expect(() => ac.setGrants(grants)).not.toThrow();
    // store grants (1) to a constant.
    const grants1 = ac.getGrants();
    // ensure to reset grants
    ac.reset();
    expect(ac.getGrants()).toEqual({});
    // now build the same grants via chained methods...
    ac.grant('viewer')
      .readOwn('account')
      .grant('user')
      .extend('viewer')
      .updateOwn('account')
      .grant('admin')
      .extend('user')
      .create('account')
      .delete('account');
    const grants2 = ac.getGrants();
    // and compare...
    expect(grants1).toEqual(grants2);
  });

  test('throw if a role attempts to extend itself', () => {
    let ac = new AccessControl();
    helper.expectACError(() => ac.grant('user').extend('user'));

    const grants = { user: { $extend: ['user'] } };
    helper.expectACError(() => new AccessControl(grants));
    ac = new AccessControl();
    helper.expectACError(() => ac.setGrants(grants));
  });

  test('throw on cross-role inheritance', () => {
    // test with chained methods

    let ac = new AccessControl();
    ac.grant(['user', 'admin']).createOwn('video');
    // make sure roles are created
    expect(ac.getRoles().length).toEqual(2);

    // direct cross-inheritance test
    ac.grant('admin').extend('user');
    helper.expectACError(() => ac.grant('user').extend('admin'));

    // deeper cross-inheritance test
    ac.grant(['editor', 'viewer', 'sa']).createOwn('image');
    ac.grant('sa').extend('editor');
    ac.grant('editor').extend('viewer');
    helper.expectACError(() => ac.grant('viewer').extend('sa'));

    // test with initial grants object

    // direct cross-inheritance test
    // user » admin » user
    let grants: IGrants = {
      user: {
        $extend: ['admin']
      },
      admin: {
        $extend: ['user']
      }
    };
    helper.expectACError(() => new AccessControl(grants));
    ac = new AccessControl();
    helper.expectACError(() => ac.setGrants(grants));

    // deeper cross-inheritance test
    // user » sa » editor » viewer » user
    grants = {
      user: {
        $extend: ['sa']
      },
      sa: {
        $extend: ['editor']
      },
      editor: {
        $extend: ['viewer']
      },
      viewer: {
        $extend: ['user']
      }
    };
    helper.expectACError(() => new AccessControl(grants));
    ac = new AccessControl();
    helper.expectACError(() => ac.setGrants(grants));

    // viewer » editor » user » sa » editor
    grants = {
      user: {
        $extend: ['sa']
      },
      sa: {
        $extend: ['editor']
      },
      editor: {
        $extend: ['user']
      },
      viewer: {
        $extend: ['editor']
      }
    };
    helper.expectACError(() => new AccessControl(grants));
    ac = new AccessControl();
    helper.expectACError(() => ac.setGrants(grants));
  });

  test('throw if grant or deny objects are invalid', () => {
    const ac = new AccessControl();
    let o;

    o = {
      role: '', // invalid role, should be non-empty string or array
      resource: 'post',
      action: 'create:any',
      attributes: ['*'] // grant only
    };
    expect(() => ac.grant(o)).toThrow();
    expect(() => ac.deny(o)).toThrow();

    o = {
      role: 'moderator',
      resource: null, // invalid resource, should be non-empty string
      action: 'create:any',
      attributes: ['*'] // grant only
    };
    expect(() => ac.grant(o)).toThrow();
    expect(() => ac.deny(o)).toThrow();

    o = {
      role: 'admin',
      resource: 'post',
      action: 'bad action:any', // invalid action *name* (space) — §6 allows custom names but not bad chars
      attributes: ['*'] // grant only
    };
    expect(() => ac.grant(o)).toThrow();
    expect(() => ac.deny(o)).toThrow();

    // §6: a custom (non-CRUD) action name like 'put' is now valid
    expect(() =>
      ac.grant({ role: 'admin', resource: 'post', action: 'put:any', attributes: ['*'] })
    ).not.toThrow();

    o = {
      role: 'admin',
      resource: 'post',
      action: null, // action is required
      attributes: ['*'] // grant only
    };
    expect(() => ac.grant(o)).toThrow();
    expect(() => ac.deny(o)).toThrow();

    o = {
      role: 'admin',
      resource: 'post',
      action: 'create:all', // invalid possession, should be any|own or omitted
      attributes: ['*'] // grant only
    };
    expect(() => ac.grant(o)).toThrow();
    expect(() => ac.deny(o)).toThrow();

    o = {
      role: 'admin2',
      resource: 'post',
      action: 'create', // possession omitted, will be set to any
      attributes: ['*'] // grant only
    };
    expect(() => ac.grant(o)).not.toThrow();
    expect(ac.can('admin2').createAny('post').granted).toEqual(true);
    // possession "any" will also return granted=true for "own"
    expect(ac.can('admin2').createOwn('post').granted).toEqual(true);
    expect(() => ac.deny(o)).not.toThrow();
  });

  test('Check with multiple roles changes grant list (issue #2)', () => {
    const ac = new AccessControl();
    ac.grant('admin').updateAny('video').grant(['user', 'admin']).updateOwn('video');

    // Admin can update any video
    expect(ac.can(['admin']).updateAny('video').granted).toEqual(true);

    // console.log('grants before', JSON.stringify(ac.getGrants(), null, '  '));

    // This check actually changes the underlying grants
    ac.can(['user', 'admin']).updateOwn('video');

    // console.log('grants after', JSON.stringify(ac.getGrants(), null, '  '));

    // Admin can update any or own video
    expect(ac.can(['admin']).updateAny('video').granted).toEqual(true);
    expect(ac.can(['admin']).updateOwn('video').granted).toEqual(true);
  });

  test('grant/deny multiple roles and multiple resources', () => {
    const ac = new AccessControl();

    ac.grant('admin, user').createAny('profile, video');
    expect(ac.can('admin').createAny('profile').granted).toEqual(true);
    expect(ac.can('admin').createAny('video').granted).toEqual(true);
    expect(ac.can('user').createAny('profile').granted).toEqual(true);
    expect(ac.can('user').createAny('video').granted).toEqual(true);

    ac.grant('admin, user').createAny('profile, video', '*,!id');
    expect(ac.can('admin').createAny('profile').attributes).toEqual(['*', '!id']);
    expect(ac.can('admin').createAny('video').attributes).toEqual(['*', '!id']);
    expect(ac.can('user').createAny('profile').attributes).toEqual(['*', '!id']);
    expect(ac.can('user').createAny('video').attributes).toEqual(['*', '!id']);

    ac.deny('admin, user').readAny('photo, book', '*,!id');
    expect(ac.can('admin').readAny('photo').attributes).toEqual([]);
    expect(ac.can('admin').readAny('book').attributes).toEqual([]);
    expect(ac.can('user').readAny('photo').attributes).toEqual([]);
    expect(ac.can('user').readAny('book').attributes).toEqual([]);

    expect(ac.can('user').createAny('non-existent').granted).toEqual(false);

    // console.log(JSON.stringify(ac.getGrants(), null, '  '));
  });

  test('Permission#filter()', () => {
    let ac = new AccessControl();
    let attrs = ['*', '!account.balance.credit', '!account.id', '!secret'];
    let data: UnknownObject = {
      name: 'Company, LTD.',
      address: {
        city: 'istanbul',
        country: 'TR'
      },
      account: {
        id: 33,
        taxNo: 12345,
        balance: {
          credit: 100,
          deposit: 0
        }
      },
      secret: {
        value: 'hidden'
      }
    };
    ac.grant('user').createOwn('company', attrs);
    let permission = ac.can('user').createOwn('company');
    expect(permission.granted).toEqual(true);
    let filtered: UnknownObject = permission.filter(data);
    expect(filtered.name).toEqual(expect.any(String));
    expect(filtered.address).toEqual(expect.any(Object));
    expect(filtered.address.city).toEqual('istanbul');
    expect(filtered.account).toBeDefined();
    expect(filtered.account.id).toBeUndefined();
    expect(filtered.account.balance).toBeDefined();
    expect(filtered.account.credit).toBeUndefined();
    expect(filtered.secret).toBeUndefined();

    ac.deny('user').createOwn('company');
    permission = ac.can('user').createOwn('company');
    expect(permission.granted).toEqual(false);
    filtered = permission.filter(data);
    expect(filtered).toEqual({});

    // filtering array of objects
    ac = new AccessControl();
    attrs = ['*', '!id'];
    data = [
      { id: 1, name: 'x', age: 30 },
      { id: 2, name: 'y', age: 31 },
      { id: 3, name: 'z', age: 32 }
    ];
    ac.grant('user').createOwn('account', ['*']).updateOwn('account', attrs);
    permission = ac.can('user').updateOwn('account');
    filtered = permission.filter(data);
    expect(filtered).toEqual(expect.any(Array));
    expect(filtered.length).toEqual(data.length);
  });

  // gh #92 / #83 — filter() must return a PLAIN deep clone built from own
  // enumerable properties only. Framework/ODM internals living on the prototype
  // (Mongoose's `$__`/`$isNew`, BSON getters, etc.) must NOT leak into the
  // filtered output, and the source document must be left untouched.
  test('Permission#filter() returns a plain clone, dropping prototype internals (#92/#83)', () => {
    // a Mongoose-like document: real data as own props, internals on the prototype
    class Doc {
      get $__() {
        return { strictMode: true };
      }
      get $isNew() {
        return false;
      }
      constructor(
        public id: number,
        public name: string,
        public secret: string
      ) {}
    }
    const ac = new AccessControl();
    ac.grant('user').readOwn('account', ['*', '!secret']);
    const doc = new Doc(1, 'onur', 'topsecret');

    const out = ac.can('user').readOwn('account').filter(doc) as UnknownObject;
    expect(out.name).toEqual('onur');
    expect(out.id).toEqual(1);
    expect(out.secret).toBeUndefined(); // negated attribute removed
    expect(out.$__).toBeUndefined(); // prototype getter dropped
    expect(out.$isNew).toBeUndefined();
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype); // plain object, not a Doc
    // source document is left intact (filter clones, never mutates)
    expect(out).not.toBe(doc);
    expect(doc.secret).toEqual('topsecret');
  });

  test('union granted attributes for extended roles, on query', () => {
    const ac = new AccessControl();
    const restrictedAttrs = ['*', '!id', '!pwd'];
    // grant user restricted attrs
    ac.grant('user')
      .updateAny('video', restrictedAttrs)
      // extend admin with user as is (same attributes)
      .grant('admin')
      .extend('user');
    // admin should have the same restricted attributes
    expect(ac.can('admin').updateAny('video').attributes).toEqual(restrictedAttrs);
    // grant admin unrestricted attrs (['*'])
    ac.grant('admin').updateAny('video');
    // union'ed attributes should be ['*']
    expect(ac.can('admin').updateAny('video').attributes).toEqual(['*']);

    ac.grant('editor').updateAny('video', ['*', '!pwd', 'title']).extend('user');
    // 'title' is redundant since we have '*'.
    // '!pwd' exists in both attribute lists, so it should exist in union.
    expect(ac.can('editor').updateAny('video').attributes).toEqual(['*', '!pwd']);

    ac.grant('role1')
      .createOwn('photo', ['image', 'name'])
      .grant('role2')
      .createOwn('photo', ['name', '!location']) // '!location' is redundant here
      .grant('role3')
      .createOwn('photo', ['*', '!location'])
      .grant('role4')
      .extend(['role1', 'role2'])
      .grant('role5')
      .extend(['role1', 'role2', 'role3']);
    // console.log(ac.can('role4').createOwn('photo').attributes);
    // expect(ac.can('role4').createOwn('photo').attributes).toEqual(['image', 'name']);
    expect(ac.can('role5').createOwn('photo').attributes).toEqual(['*', '!location']);
  });

  test('AccessControl.filter()', () => {
    const o = {
      name: 'John',
      age: 30,
      account: {
        id: 1,
        country: 'US'
      }
    };
    const x: UnknownObject = AccessControl.filter(o, ['*', '!account.id', '!age']);
    expect(x.name).toEqual('John');
    expect(x.account.id).toBeUndefined();
    expect(x.account.country).toEqual('US');

    expect(o.account.id).toEqual(1);
    expect(o).not.toEqual(x);
  });

  test('AccessControl#lock(), Access#lock()', () => {
    let ac: AccessControl;

    function _inoperative() {
      helper.expectACError(() => ac.setGrants({}));
      helper.expectACError(() => ac.reset());
      helper.expectACError(() => ac.grant('editor'));
      helper.expectACError(() => ac.deny('admin'));
      helper.expectACError(() => ac.extendRole('admin', 'user'));
      helper.expectACError(() => ac.removeRoles(['admin']));
      helper.expectACError(() => ac.removeResources(['video']));

      expect(() => ((ac as any)._grants.hacker = { account: { 'read:any': ['*'] } })).toThrow();
      expect(ac.hasRole('hacker')).toBe(false);
    }

    function _operative() {
      expect(ac.getRoles()).toContain('user');
      expect(ac.getRoles()).toContain('admin');
      expect(ac.getResources()).toContain('video');
      expect(ac.getInheritedRolesOf('admin')).not.toContain('user');
    }

    function _test() {
      _inoperative();
      _operative();
    }

    // locking with Access#lock
    ac = new AccessControl();
    ac.grant('user').createAny('video').grant('admin').createAny('photo').lock();
    _test();

    // locking with AccessControl#lock
    ac = new AccessControl();
    ac.grant('user').createAny('video').grant('admin').createAny('photo');
    ac.lock();
    _test();

    // locking when grants not specified
    ac = new AccessControl();
    helper.expectACError(() => ac.lock()); // cannot lock empty grants
    ac.setGrants({ admin: { account: {} } }).lock();
    _inoperative();

    // locking when grants are _isLocked is altered
    ac = new AccessControl();
    ac.setGrants({ admin: { account: {} } });
    (ac as UnknownObject)._isLocked = true;
    ac.lock();
    _inoperative();

    // locking when grants are shallow frozen
    ac = new AccessControl({ admin: { account: {} } });
    Object.freeze((ac as any)._grants);
    ac.lock();
    helper.expectACError(() => ac.removeResources(['account']));
    _inoperative();

    // locking when grants are shallow frozen and _isLocked is altered
    ac = new AccessControl({ admin: { account: {} } });
    (ac as UnknownObject)._isLocked = true;
    Object.freeze((ac as any)._grants);
    ac.lock();
    helper.expectACError(() => ac.removeResources(['account']));
    _inoperative();
  });

  test('Action / Possession enumerations', () => {
    expect(Action).toEqual(expect.any(Object));
    expect(Possession).toEqual(expect.any(Object));
    expect(Possession.ANY).toBe('any');
    expect(Possession.OWN).toBe('own');
  });

  test('AccessControlError', () => {
    helper.expectACError(() => {
      throw new AccessControlError();
    });
    expect(new AccessControlError().message).toEqual('');
  });
});
