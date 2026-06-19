/**
 *  Test Suite: mutation kills.
 *  Asserts exact error messages, structured error fields, operator boundaries,
 *  and parser/validator edges so mutated operators/strings/conditions are caught.
 */

import { AccessControl, Emitter, ErrorCode } from '../src/index.js';
import {
  compileCondition,
  deepFreeze,
  detail,
  evaluateCondition,
  extendRole,
  filter,
  getActions,
  getInspectedGrants,
  getNonExistentRoles,
  getResources,
  getRoleHierarchyOf,
  hasValidNames,
  impliedStar,
  isFilledStringArray,
  normalizeAccessInfo,
  normalizeActionPossession,
  normalizeName,
  normalizeQueryInfo,
  preCreateRoles,
  resetAttributes,
  validName
} from '../src/utils/index.js';

const VERBOSE = { safeErrors: false } as const;

const ev = (expr: any, ctx: any = {}) => evaluateCondition(compileCondition(expr), ctx);

/** Runs `fn`, returns the thrown error (fails if it doesn't throw). */
function grab(fn: () => unknown): any {
  try {
    fn();
  } catch (e) {
    return e;
  }
  throw new Error('expected function to throw');
}

describe('Mutation kills: condition operators (boundaries)', () => {
  test('equality', () => {
    expect(ev('$.n == 5', { n: 5 })).toBe(true);
    expect(ev('$.n == 5', { n: 6 })).toBe(false);
    expect(ev('$.n != 5', { n: 6 })).toBe(true);
    expect(ev('$.n != 5', { n: 5 })).toBe(false);
  });

  test('ordering boundaries (distinguish > >= < <=)', () => {
    expect(ev('$.n > 5', { n: 6 })).toBe(true);
    expect(ev('$.n > 5', { n: 5 })).toBe(false); // kills > -> >=
    expect(ev('$.n >= 5', { n: 5 })).toBe(true); // kills >= -> >
    expect(ev('$.n >= 5', { n: 4 })).toBe(false);
    expect(ev('$.n < 5', { n: 4 })).toBe(true);
    expect(ev('$.n < 5', { n: 5 })).toBe(false); // kills < -> <=
    expect(ev('$.n <= 5', { n: 5 })).toBe(true); // kills <= -> <
    expect(ev('$.n <= 5', { n: 6 })).toBe(false);
  });

  test('in / contains', () => {
    expect(ev('$.r in [a, b]', { r: 'a' })).toBe(true);
    expect(ev('$.r in [a, b]', { r: 'c' })).toBe(false);
    expect(ev('$.tags contains red', { tags: ['red'] })).toBe(true);
    expect(ev('$.tags contains red', { tags: ['blue'] })).toBe(false);
    expect(ev('$.s contains ell', { s: 'hello' })).toBe(true);
    expect(ev('$.s contains zzz', { s: 'hello' })).toBe(false);
  });

  test('string operators', () => {
    expect(ev('$.s matches ^rep', { s: 'report' })).toBe(true);
    expect(ev('$.s matches ^xyz', { s: 'report' })).toBe(false);
    expect(ev('$.s startsWith re', { s: 'report' })).toBe(true);
    expect(ev('$.s startsWith xx', { s: 'report' })).toBe(false);
    expect(ev('$.s endsWith ort', { s: 'report' })).toBe(true);
    expect(ev('$.s endsWith xx', { s: 'report' })).toBe(false);
    expect(grab(() => ev('$.s matches (', { s: 'x' })).message).toContain(
      'Invalid regular expression'
    );
  });

  test('before / after with numbers, times and dates', () => {
    expect(ev('$.n before 5', { n: 4 })).toBe(true);
    expect(ev('$.n before 5', { n: 5 })).toBe(false);
    expect(ev('$.n after 5', { n: 6 })).toBe(true);
    expect(ev('$.n after 5', { n: 5 })).toBe(false);
    expect(ev('$.t after 09:00', { t: '10:00' })).toBe(true);
    expect(ev('$.t after 09:00', { t: '08:00' })).toBe(false);
    expect(ev('$.d before 2020-06-01', { d: '2020-01-01' })).toBe(true);
    expect(ev('$.d before 2020-06-01', { d: '2021-01-01' })).toBe(false);
  });

  test('between inclusive boundaries + overnight time wrap', () => {
    expect(ev('$.n between [1, 10]', { n: 1 })).toBe(true); // lower inclusive
    expect(ev('$.n between [1, 10]', { n: 10 })).toBe(true); // upper inclusive
    expect(ev('$.n between [1, 10]', { n: 0 })).toBe(false);
    expect(ev('$.n between [1, 10]', { n: 11 })).toBe(false);
    // wrap window 22:00–06:00
    expect(ev('$.t between [22:00, 06:00]', { t: '23:00' })).toBe(true);
    expect(ev('$.t between [22:00, 06:00]', { t: '05:00' })).toBe(true);
    expect(ev('$.t between [22:00, 06:00]', { t: '12:00' })).toBe(false);
    // non-wrap time window 09:00–17:00
    expect(ev('$.t between [09:00, 17:00]', { t: '12:00' })).toBe(true);
    expect(ev('$.t between [09:00, 17:00]', { t: '08:00' })).toBe(false);
  });

  test('cidr / ip membership boundaries', () => {
    expect(ev('$.ip cidr 10.0.0.0/8', { ip: '10.255.0.1' })).toBe(true);
    expect(ev('$.ip cidr 10.0.0.0/8', { ip: '11.0.0.1' })).toBe(false);
    expect(ev('$.ip cidr 0.0.0.0/0', { ip: '1.2.3.4' })).toBe(true); // /0 matches all
    expect(ev('$.ip cidr 1.2.3.4/32', { ip: '1.2.3.4' })).toBe(true); // /32 exact
    expect(ev('$.ip cidr 1.2.3.4/32', { ip: '1.2.3.5' })).toBe(false);
    expect(ev('$.ip cidr 1.2.3.4', { ip: '1.2.3.4' })).toBe(true); // no slash exact
    expect(ev('$.ip cidr 1.2.3.4', { ip: '1.2.3.5' })).toBe(false);
    expect(ev('$.ip cidr 10.0.0.0/8', { ip: 'nope' })).toBe(false); // non-ipv4
    expect(ev('$.ip in [10.0.0.0/8, 192.168.0.0/16]', { ip: '192.168.1.1' })).toBe(true);
    expect(ev('$.ip in [10.0.0.0/8]', { ip: '8.8.8.8' })).toBe(false);
  });

  test('not modifier flips the result', () => {
    expect(ev('$.r not in [a, b]', { r: 'c' })).toBe(true);
    expect(ev('$.r not in [a, b]', { r: 'a' })).toBe(false);
  });

  test('and / or short-circuit semantics', () => {
    expect(ev({ and: ['$.a == 1', '$.b == 2'] }, { a: 1, b: 2 })).toBe(true);
    expect(ev({ and: ['$.a == 1', '$.b == 2'] }, { a: 1, b: 3 })).toBe(false);
    expect(ev({ or: ['$.a == 1', '$.b == 2'] }, { a: 9, b: 2 })).toBe(true);
    expect(ev({ or: ['$.a == 1', '$.b == 2'] }, { a: 9, b: 9 })).toBe(false);
  });
});

describe('Mutation kills: condition compiler messages & edges', () => {
  test('parser edges: quotes, lists, whitespace', () => {
    expect(compileCondition('$.s == "a b"')).toEqual(['$.s', '==', 'a b']);
    expect(compileCondition("$.s == 'a b'")).toEqual(['$.s', '==', 'a b']);
    expect(compileCondition('$.x in [a, b, c]')).toEqual(['$.x', 'in', ['a', 'b', 'c']]);
    expect(compileCondition('  $.x   ==   1  ')).toEqual(['$.x', '==', 1]);
    expect(compileCondition('$.flag == true')).toEqual(['$.flag', '==', true]);
    expect(compileCondition('$.flag == false')).toEqual(['$.flag', '==', false]);
    expect(compileCondition('$.v == null')).toEqual(['$.v', '==', null]);
    expect(compileCondition('$.n == -3.5')).toEqual(['$.n', '==', -3.5]);
  });

  test('compiler error messages', () => {
    expect(grab(() => compileCondition("$.s == 'oops")).message).toContain('Unterminated quote');
    expect(grab(() => compileCondition('$.x in [a, b')).message).toContain('Unterminated "["');
    expect(grab(() => compileCondition('$.x ==')).message).toContain(
      'Invalid condition expression'
    );
    expect(grab(() => compileCondition('$.x bogus 1')).message).toContain(
      'Unknown operator "bogus"'
    );
    expect(grab(() => compileCondition('$.x in [a,,b]')).message).toContain('Empty operand');
    expect(grab(() => compileCondition('$.v between [1]')).message).toContain('exactly two bounds');
    expect(grab(() => compileCondition('$.v between [5, 2]')).message).toContain(
      'Invalid "between" range'
    );
    expect(grab(() => compileCondition('$.ip cidr 10.0.0/8')).message).toContain('Malformed CIDR');
    expect(grab(() => compileCondition('$.ip cidr 10.0.0.0/99')).message).toContain(
      'Invalid CIDR prefix'
    );
    expect(grab(() => compileCondition('$.ip cidr 999.0.0.0/8')).message).toContain(
      'Invalid IPv4 octet'
    );
    expect(grab(() => evaluateCondition('$.x == 1' as any)).message).toContain('must be compiled');
    expect(grab(() => evaluateCondition({ fn: 'x' } as any)).message).toContain('async');
  });
});

describe('Mutation kills: validation messages, fields & boundaries', () => {
  test('normalizeName: valid passes, invalid throws with message', () => {
    expect(normalizeName('camelCase')).toBe('camelCase');
    expect(normalizeName('kebab-case')).toBe('kebab-case');
    expect(normalizeName('  trimmed  ')).toBe('trimmed');
    expect(grab(() => normalizeName('')).message).toContain('non-empty string');
    expect(grab(() => normalizeName(123 as any)).message).toContain('non-empty string');
    expect(grab(() => normalizeName('bad name')).message).toContain('Allowed characters');
    expect(grab(() => normalizeName('a/b/c', true)).message).toContain('single level');
    expect(grab(() => normalizeName('_/x', true)).message).toContain('reserved');
    expect(normalizeName('grp/role', true)).toBe('grp/role');
  });

  test('validName boolean flag + hasValidNames', () => {
    expect(validName('ok')).toBe(true);
    expect(validName('bad name', false)).toBe(false); // no throw, returns false
    expect(grab(() => validName('bad name')).message).toContain('Allowed characters');
    expect(hasValidNames(['a', 'b'])).toBe(true);
    expect(hasValidNames(['a', 'bad name'], false)).toBe(false);
  });

  test('normalizeActionPossession: defaults, split, invalid', () => {
    expect((normalizeActionPossession({ action: 'read' }) as any).possession).toBe('any');
    expect((normalizeActionPossession({ action: 'read:own' }) as any).possession).toBe('own');
    expect(grab(() => normalizeActionPossession({ action: '' })).message).toContain(
      'Invalid action'
    );
    expect(grab(() => normalizeActionPossession({ action: 'read:all' })).message).toContain(
      'Invalid action possession'
    );
  });

  test('normalizeQueryInfo / normalizeAccessInfo: messages + defaults', () => {
    expect(grab(() => normalizeQueryInfo('x' as any)).message).toContain('Invalid IQueryInfo');
    expect(grab(() => normalizeQueryInfo({ role: [] } as any)).message).toContain('Invalid role');
    expect(grab(() => normalizeQueryInfo({ role: 'r', resource: '' } as any)).message).toContain(
      'Invalid resource'
    );
    expect(grab(() => normalizeAccessInfo('x' as any)).message).toContain('Invalid IAccessInfo');
    // attributes default to ['*'] when omitted
    expect(normalizeAccessInfo({ role: 'r', resource: 's' }).attributes).toEqual(['*']);
    // effect:'deny' marks denied
    expect(normalizeAccessInfo({ role: 'r', resource: 's', effect: 'deny' } as any).denied).toBe(
      true
    );
  });
});

describe('Mutation kills: roles & grants messages + structured fields', () => {
  test('getRoleHierarchyOf error messages + err.role', () => {
    const e = grab(() => getRoleHierarchyOf({}, 'ghost'));
    expect(e.message).toContain('Role not found');
    expect(e.role).toBe('ghost');
    expect(grab(() => getRoleHierarchyOf({ a: { $extend: ['a'] } } as any, 'a')).message).toContain(
      'by itself'
    );
    const cross: any = { a: { $extend: ['b'] }, b: { $extend: ['a'] } };
    expect(grab(() => getRoleHierarchyOf(cross, 'a')).message).toContain('Cross inheritance');
  });

  test('extendRole + getNonExistentRoles', () => {
    expect(grab(() => extendRole({}, [], ['x'])).message).toContain('Invalid role');
    expect(getNonExistentRoles({ a: {} } as any, ['a', 'b'])).toEqual(['b']);
    expect(getNonExistentRoles({ a: {} } as any, ['a'])).toEqual([]);
  });

  test('grants object validation messages + err.action/role', () => {
    expect(grab(() => getInspectedGrants(42)).message).toContain('Expected an array or object');
    const e1 = grab(() => getInspectedGrants({ admin: 'nope' }));
    expect(e1.message).toContain('Invalid role definition');
    expect(e1.role).toBe('admin');
    const e2 = grab(() => getInspectedGrants({ admin: { post: { read: ['x'] } } }));
    expect(e2.message).toContain('Invalid grant rule');
    expect(e2.action).toBe('read');
    expect(grab(() => getInspectedGrants({ admin: { post: { read: 'x' } } })).message).toContain(
      'expected an array'
    );
    const e3 = grab(() =>
      getInspectedGrants({ admin: { post: { read: [{ possession: 'all', attributes: ['*'] }] } } })
    );
    expect(e3.message).toContain('Invalid possession');
    const e4 = grab(() =>
      getInspectedGrants({ admin: { post: { read: [{ effect: 'maybe', attributes: ['*'] }] } } })
    );
    expect(e4.message).toContain('Invalid effect');
    expect(
      grab(() => getInspectedGrants({ admin: { post: { read: [{ attributes: [''] }] } } })).message
    ).toContain('Invalid attributes');
  });
});

describe('Mutation kills: AccessControl messages & lock', () => {
  test('locked mutators throw the lock message', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    ac.lock();
    expect(grab(() => ac.setGrants({})).message).toContain('locked');
    expect(grab(() => ac.reset()).message).toContain('locked');
    expect(grab(() => ac.grant('x')).message).toContain('locked');
    expect(grab(() => ac.removeRoles('admin')).message).toContain('locked');
    expect(grab(() => ac.require('$.a == 1')).message).toContain('locked');
  });

  test('lock() requires a non-empty grants model', () => {
    expect(grab(() => new AccessControl().lock()).message).toContain('Cannot lock empty');
  });

  test('removeRoles validation + hasRole/hasResource', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    expect(grab(() => ac.removeRoles([])).message).toContain('Invalid role');
    expect(grab(() => ac.removeRoles('ghost')).message).toContain('non-existing role');
    expect(ac.hasRole('admin')).toBe(true);
    expect(ac.hasRole('ghost')).toBe(false);
    expect(ac.hasResource('post')).toBe(true);
    expect(ac.hasResource('ghost')).toBe(false);
  });

  test('can() rejects explicit undefined role', () => {
    expect(grab(() => new AccessControl().can(undefined as any)).message).toContain('undefined');
  });
});

describe('Mutation kills: Permission / Access / Emitter / notation / generic', () => {
  test('granted boundary: has a non-negated attribute vs empty/deny-all', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('p', ['*', '!secret']);
    ac.grant('u').createAny('p', []); // deny-all ⇒ empty attributes
    expect(ac.can('u').readAny('p').granted).toBe(true);
    expect(ac.can('u').createAny('p').granted).toBe(false);
    expect(ac.can('u').readAny('p').attributes).toEqual(['*', '!secret']);
  });

  test('sync access to a custom-fn permission throws asyncRequired (message + field)', () => {
    const ac = new AccessControl();
    ac.defineCondition('f', () => true);
    ac.grant('u').where({ fn: 'f' }).readAny('q', ['*']);
    const e = grab(() => ac.can('u').readAny('q').granted);
    expect(e.message).toContain('custom/async');
    expect(e.asyncRequired).toBe(true);
  });

  test('grantedAsync reuses a sync-resolved permission (no re-resolve)', async () => {
    const ac = new AccessControl();
    let calls = 0;
    ac.grant('u').where('$.x == 1').readAny('p', ['*']);
    ac.on('access', () => calls++);
    const p = ac.can('u', { x: 1 }).readAny('p');
    expect(p.granted).toBe(true); // sync resolve ⇒ 1 access event
    expect(await p.grantedAsync).toBe(true); // cached ⇒ no second event
    expect(calls).toBe(1);
  });

  test('change event detail carries role/resource/action', () => {
    const ac = new AccessControl();
    const details: any[] = [];
    ac.on('change', (e: any) => details.push(e.detail));
    ac.grant('admin').readAny('post', ['*']);
    expect(details[0]).toMatchObject({ role: 'admin', resource: 'post', action: 'read' });
  });

  test('lock(): isLocked flips, model still queryable, empty lock rejected', () => {
    const ac = new AccessControl();
    ac.grant('a').readAny('b', ['*']);
    expect(ac.isLocked).toBe(false);
    ac.lock();
    expect(ac.isLocked).toBe(true);
    expect(ac.can('a').readAny('b').granted).toBe(true);
    expect(grab(() => new AccessControl().lock()).message).toContain('Cannot lock empty');
  });

  test('permission.filter keeps allowed attrs, drops the rest (object + array + denied)', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('p', ['*', '!secret']);
    ac.grant('u').createAny('p', []);
    expect(ac.can('u').readAny('p').filter({ a: 1, secret: 2 })).toEqual({ a: 1 });
    expect(
      ac
        .can('u')
        .readAny('p')
        .filter([
          { a: 1, secret: 2 },
          { a: 3, secret: 4 }
        ])
    ).toEqual([{ a: 1 }, { a: 3 }]);
    expect(ac.can('u').createAny('p').filter({ a: 1 })).toEqual({});
  });

  test('isFilledStringArray edges', () => {
    expect(isFilledStringArray(['x'])).toBe(true);
    expect(isFilledStringArray(['   '])).toBe(false); // whitespace-only ⇒ false
    expect(isFilledStringArray([1 as any])).toBe(false); // non-string ⇒ false
  });

  test('Emitter.has reflects add/remove; emit reaches listeners', () => {
    const em = new Emitter();
    const calls: any[] = [];
    const fn = (e: any) => calls.push(e);
    expect(em.has('access')).toBe(false);
    em.on('access', fn);
    expect(em.has('access')).toBe(true);
    em.emit('access', { name: 'access', timestamp: 1 } as any);
    expect(calls).toHaveLength(1);
    em.off('access', fn);
    expect(em.has('access')).toBe(false); // size 0
  });

  test('can(IQueryInfo) invalid shapes throw with messages', () => {
    expect(grab(() => new AccessControl().can({} as any)).message).toContain('Invalid IQueryInfo');
    expect(grab(() => new AccessControl().can(123 as any)).message).toContain('Invalid role');
  });
});

describe('Mutation kills: AccessControl strict matrix', () => {
  test('default policy: checks on, roles on, actions/resources off', () => {
    const ac = new AccessControl({}, { policy: { ownerField: 'o' } });
    ac.grant('u').readOwn('doc', ['*']);
    expect(ac.can('u').readOwn('doc').granted).toBe(false); // checks on ⇒ no record denies
    expect(grab(() => ac.can('ghost').readAny('doc').granted).message).toContain('Role not found'); // roles on
    expect(ac.can('u').action('frob', 'doc').granted).toBe(false); // actions off ⇒ no throw
    expect(ac.can('u').readAny('ghostres').granted).toBe(false); // resources off ⇒ no throw
  });

  test('strict:true turns every guard on', () => {
    const ac = new AccessControl({}, { policy: { ownerField: 'o', strict: true } });
    ac.grant('u').readOwn('doc', ['*']);
    ac.grant('u').action('publish', 'doc', ['*']);
    expect(ac.can('u').readOwn('doc').granted).toBe(false); // checks on
    expect(grab(() => ac.can('ghost').readAny('doc').granted).message).toContain('Role not found');
    expect(grab(() => ac.can('u').action('frob', 'doc').granted).message).toContain(
      'Unknown action'
    );
    expect(grab(() => ac.can('u').readAny('ghostres').granted).message).toContain(
      'Unknown resource'
    );
  });

  test('strict:false turns every guard off', () => {
    const ac = new AccessControl({}, { policy: { ownerField: 'o', strict: false } });
    ac.grant('u').readOwn('doc', ['*', '!x']);
    expect(ac.can('u').readOwn('doc').granted).toBe(true); // checks off ⇒ v2 (no record ok)
    expect(ac.can('ghost').readAny('doc').granted).toBe(false); // roles off ⇒ no throw
  });

  test('per-key strict: absent keys fall back to defaults (checks/roles on)', () => {
    // checks key absent ⇒ checks stays ON
    const a = new AccessControl({}, { policy: { ownerField: 'o', strict: { roles: true } } });
    a.grant('u').readOwn('doc', ['*']);
    expect(a.can('u').readOwn('doc').granted).toBe(false);
    // roles key absent ⇒ roles stays ON
    const b = new AccessControl({}, { policy: { strict: { checks: true } } });
    b.grant('u').readAny('doc', ['*']);
    expect(grab(() => b.can('ghost').readAny('doc').granted).message).toContain('Role not found');
    // checks:false explicit ⇒ ownership not enforced
    const c = new AccessControl({}, { policy: { ownerField: 'o', strict: { checks: false } } });
    c.grant('u').readOwn('doc', ['*']);
    expect(c.can('u').readOwn('doc').granted).toBe(true);
  });
});

describe('Mutation kills: AccessControl lock + change details + introspection', () => {
  test('all mutators throw when locked', () => {
    const make = () => {
      const ac = new AccessControl();
      ac.grant('admin').readAny('post', ['*']);
      ac.lock();
      return ac;
    };
    const msg = 'locked';
    expect(grab(() => make().setGrants({})).message).toContain(msg);
    expect(grab(() => make().reset()).message).toContain(msg);
    expect(grab(() => make().grant('x')).message).toContain(msg);
    expect(grab(() => make().deny('x')).message).toContain(msg);
    expect(grab(() => make().removeRoles('admin')).message).toContain(msg);
    expect(grab(() => make().extendRole('admin', 'admin')).message).toContain(msg);
    expect(grab(() => make().setup({ roles: ['x'] })).message).toContain(msg);
    expect(grab(() => make().require('$.a == 1')).message).toContain(msg);
    expect(grab(() => make().category('c').require('$.a == 1')).message).toContain(msg);
    expect(grab(() => make().resource('r').require('$.a == 1')).message).toContain(msg);
    expect(grab(() => make().removeGroup('g')).message).toContain(msg);
    expect(grab(() => make().removeCategory('c')).message).toContain(msg);
    expect(grab(() => make().defineCondition('f', () => true)).message).toContain(msg);
  });

  test('change events carry the right type + detail per mutation', () => {
    const ac = new AccessControl();
    const log: any[] = [];
    ac.on('change', (e: any) => log.push([e.type, e.detail]));
    ac.grant('admin').readAny('post', ['*']);
    ac.deny('admin').deleteAny('post');
    ac.grant('user').readAny('post', ['*']);
    ac.extendRole('admin', 'user');
    ac.setGrants({ a: { b: { read: [{ attributes: ['*'] }] } } });
    ac.setup({ roles: ['guest'] });
    ac.require('$.x == 1');
    ac.category('media').require('$.y == 1');
    ac.removeCategory('media');
    ac.reset();
    const types = log.map((l) => l[0]);
    expect(types).toEqual([
      'grant',
      'deny',
      'grant',
      'extend',
      'set_grants',
      'setup',
      'require',
      'require',
      'remove',
      'reset'
    ]);
    expect(log[0][1]).toMatchObject({ role: 'admin', resource: 'post', action: 'read' });
    expect(log[3][1]).toMatchObject({ role: 'admin', $extend: 'user' });
    expect(log[7][1]).toMatchObject({ scope: 'media' });
    expect(log[8][1]).toMatchObject({ category: 'media' });
  });

  test('introspection: groups exclude `_`; copies are detached', () => {
    const ac = new AccessControl();
    ac.setup({
      roles: { admins: ['admin'], _: ['user'] },
      resources: { media: ['photo'], _: ['p'] }
    });
    expect(ac.getGroups()).toEqual(['admins']); // `_` excluded
    expect(ac.getCategories()).toEqual(['media']);
    const roles = ac.group('admins').getRoles();
    roles.push('mutated');
    expect(ac.group('admins').getRoles()).toEqual(['admins/admin']); // copy not affected
    expect(ac.group('nope').getRoles()).toEqual([]);
  });

  test('resource()/category() validate the name', () => {
    const ac = new AccessControl();
    expect(grab(() => ac.resource('bad name')).message).toContain('Allowed characters');
    expect(grab(() => ac.category('bad name')).message).toContain('Allowed characters');
    expect(grab(() => ac.defineCondition('', () => true)).message).toContain('condition name');
    expect(grab(() => ac.defineCondition('x', 'no' as any)).message).toContain(
      'condition function'
    );
  });

  test('_removePermission validation messages', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('p', ['*']);
    expect(grab(() => (ac as any)._removePermission([])).message).toContain('Invalid resource');
    expect(grab(() => (ac as any)._removePermission('p', [])).message).toContain('Invalid role');
  });
});

describe('Mutation kills: grants object-form rules (fields + behavior)', () => {
  test('possession/effect/condition honored + structured err.action', () => {
    const ac = new AccessControl({}, { policy: { ownerField: 'o' } });
    ac.setGrants({
      u: {
        doc: {
          read: [
            { possession: 'any', attributes: ['*'] },
            { possession: 'own', effect: 'deny', attributes: ['secret'] }
          ]
        }
      }
    } as any);
    // any grant present ⇒ granted; deny:own only subtracts when owned
    expect(ac.can('u', { user: { id: 1 }, doc: { o: 2 } }).readAny('doc').granted).toBe(true);
    const owns = ac.can('u', { user: { id: 1 }, doc: { o: 1 } }).readOwn('doc');
    expect(owns.attributes).not.toContain('secret');

    const e1 = grab(() =>
      getInspectedGrants({ u: { d: { read: [{ possession: 'nope', attributes: ['*'] }] } } })
    );
    expect(e1.action).toBe('read');
    const e2 = grab(() =>
      getInspectedGrants({ u: { d: { read: [{ effect: 'nope', attributes: ['*'] }] } } })
    );
    expect(e2.action).toBe('read');
    const e3 = grab(() => getInspectedGrants({ u: { d: { read: [{ attributes: [''] }] } } }));
    expect(e3.action).toBe('read');
  });

  test('flat-list + object-form $extend rows; empty $extend ignored', () => {
    const list = new AccessControl([
      { role: 'editor', resource: 'doc', action: 'read:any', attributes: ['*'] },
      { role: 'admin', $extend: ['editor'] },
      { role: 'noop', $extend: [] } // empty ⇒ ignored
    ]);
    expect(list.can('admin').readAny('doc').granted).toBe(true);

    const obj = new AccessControl({
      editor: { doc: { read: [{ attributes: ['*'] }] } },
      admin: { $extend: ['editor'] }
    } as any);
    expect(obj.can('admin').readAny('doc').granted).toBe(true);
  });
});

describe('Mutation kills: condition validators, masks & coercion', () => {
  test('validateBetween enforces number/date ordering; time/equal allowed', () => {
    expect(() => compileCondition('$.n between [2, 10]')).not.toThrow();
    expect(() => compileCondition('$.n between [5, 5]')).not.toThrow(); // equal ok
    expect(grab(() => compileCondition('$.n between [10, 2]')).message).toContain(
      'Invalid "between" range'
    );
    expect(() => compileCondition('$.d between [2020-01-01, 2020-12-31]')).not.toThrow();
    expect(grab(() => compileCondition('$.d between [2020-12-31, 2020-01-01]')).message).toContain(
      'Invalid "between" range'
    );
    expect(() => compileCondition('$.t between [22:00, 06:00]')).not.toThrow(); // wrap allowed
  });

  test('cidr/ip member validation boundaries', () => {
    expect(() => compileCondition('$.ip cidr 10.0.0.0/0')).not.toThrow();
    expect(() => compileCondition('$.ip cidr 10.0.0.0/32')).not.toThrow();
    expect(grab(() => compileCondition('$.ip cidr 10.0.0.0/33')).message).toContain(
      'Invalid CIDR prefix'
    );
    expect(grab(() => compileCondition('$.ip cidr 256.0.0.0/8')).message).toContain(
      'Invalid IPv4 octet'
    );
    expect(() => compileCondition('$.ip in [10.0.0.0/8, 1.2.3.4]')).not.toThrow();
  });

  test('cidr mask math at /16, /24 boundaries', () => {
    expect(ev('$.ip cidr 192.168.1.0/24', { ip: '192.168.1.255' })).toBe(true);
    expect(ev('$.ip cidr 192.168.1.0/24', { ip: '192.168.2.0' })).toBe(false);
    expect(ev('$.ip cidr 192.168.0.0/16', { ip: '192.168.255.1' })).toBe(true);
    expect(ev('$.ip cidr 192.168.0.0/16', { ip: '192.169.0.1' })).toBe(false);
  });

  test('resolveOperand: nested paths, $ root, typed literals', () => {
    expect(ev('$.a.b.c == 5', { a: { b: { c: 5 } } })).toBe(true);
    expect(ev('$.user.id == $.doc.owner', { user: { id: 7 }, doc: { owner: 7 } })).toBe(true);
    expect(ev('$.user.id == $.doc.owner', { user: { id: 7 }, doc: { owner: 8 } })).toBe(false);
    expect(ev('$.n == 0', { n: 0 })).toBe(true); // numeric zero literal
    expect(ev('$.s == "0"', { s: '0' })).toBe(true); // quoted keeps string
  });

  test('before/after coerce non-date strings lexically', () => {
    expect(ev('$.s before m', { s: 'a' })).toBe(true);
    expect(ev('$.s before m', { s: 'z' })).toBe(false);
  });
});

describe('Mutation kills: condition parser/validator edges (round 2)', () => {
  test('empty quoted literal + space-only list + joined rhs', () => {
    expect(compileCondition('$.s == ""')).toEqual(['$.s', '==', '']); // 2-char quote
    expect(compileCondition("$.s == ''")).toEqual(['$.s', '==', '']);
    expect(compileCondition('$.x in [  ]')).toEqual(['$.x', 'in', []]); // whitespace ⇒ []
    expect(compileCondition('$.s == a b')).toEqual(['$.s', '==', 'a b']); // join with " "
  });

  test('missing rhs after a `not` modifier throws its own message', () => {
    expect(grab(() => compileCondition('$.x not in')).message).toContain(
      'Missing right-hand operand'
    );
  });

  test('canonical-leaf passthrough validation messages', () => {
    expect(grab(() => compileCondition(['$.x', '=='] as any)).message).toContain(
      'Invalid condition leaf'
    );
    expect(grab(() => compileCondition(['$.x', 'bogus', 1] as any)).message).toContain(
      'Unknown operator "bogus" in condition leaf'
    );
    // canonical leaf round-trips (idempotent)
    expect(compileCondition(['$.x', '==', 1] as any)).toEqual(['$.x', '==', 1]);
  });

  test('combinator object validation messages', () => {
    expect(grab(() => compileCondition({ and: 'x' } as any)).message).toContain(
      '"and" expects an array'
    );
    expect(grab(() => compileCondition({ or: 'x' } as any)).message).toContain(
      '"or" expects an array'
    );
    expect(grab(() => compileCondition({ bogus: 1 } as any)).message).toContain(
      'Invalid condition'
    );
  });

  test('between range: equal dates allowed; equal/255 ip octet allowed', () => {
    expect(() => compileCondition('$.d between [2020-01-01, 2020-01-01]')).not.toThrow(); // a==b ok
    expect(() => compileCondition('$.ip cidr 255.255.255.255/32')).not.toThrow(); // octet 255 ok
    expect(() => compileCondition('$.ip cidr 255.0.0.0/8')).not.toThrow();
  });

  test('between time-of-day boundaries (inclusive + wrap edges)', () => {
    // non-wrap inclusive endpoints
    expect(ev('$.t between [09:00, 17:00]', { t: '09:00' })).toBe(true); // X>=A boundary
    expect(ev('$.t between [09:00, 17:00]', { t: '17:00' })).toBe(true); // X<=B boundary
    // equal bounds: A<=B path, only the single minute matches
    expect(ev('$.t between [09:00, 09:00]', { t: '09:00' })).toBe(true);
    expect(ev('$.t between [09:00, 09:00]', { t: '10:00' })).toBe(false); // kills A<=B → A<B
    // wrap inclusive endpoints
    expect(ev('$.t between [22:00, 06:00]', { t: '22:00' })).toBe(true); // X>=A boundary (wrap)
    expect(ev('$.t between [22:00, 06:00]', { t: '06:00' })).toBe(true); // X<=B boundary (wrap)
  });

  test('now derived from a Date and from a string source', () => {
    expect(ev('$.now.year == 2019', { now: new Date('2019-05-05T10:00:00Z') })).toBe(true);
    expect(ev('$.now.year == 2019', { now: '2019-05-05T10:00:00Z' })).toBe(true);
    expect(ev('$.now.year == 2019', { now: new Date('2021-05-05T10:00:00Z') })).toBe(false);
  });
});

describe('Mutation kills: roles util messages + structured fields (round 2)', () => {
  test('getRoleHierarchyOf: no-$extend returns just self; bad extender throws', () => {
    expect(getRoleHierarchyOf({ a: {} } as any, 'a')).toEqual(['a']); // kills always-recurse
    expect(getRoleHierarchyOf({ a: { $extend: [] } } as any, 'a')).toEqual(['a']);
    const e = grab(() => getRoleHierarchyOf({ a: { $extend: ['ghost'] } } as any, 'a'));
    expect(e.message).toContain('Role not found'); // value redacted (safeErrors), in err.role
    expect(e.role).toBe('ghost');
    expect(e.code).toBe('ROLE_NOT_FOUND');
    const self = grab(() => getRoleHierarchyOf({ a: { $extend: ['a'] } } as any, 'a'));
    expect(self.message).toContain('by itself');
    expect(self.role).toBe('a');
  });

  test('extendRole: non-existent / not-found / self / cross messages + err.role', () => {
    expect(grab(() => extendRole({ a: {} } as any, 'a', ['ghost'])).message).toContain(
      'Cannot inherit non-existent role(s)'
    );
    const nf = grab(() => extendRole({ b: {} } as any, 'a', ['b']));
    expect(nf.message).toContain('Role not found'); // value redacted, in err.role
    expect(nf.role).toBe('a');
    const self = grab(() => extendRole({ a: {} } as any, 'a', ['a']));
    expect(self.message).toContain('by itself');
    expect(self.role).toBe('a');
    // cross inheritance: b extends a, then a extends b
    const g: any = { a: {}, b: {} };
    extendRole(g, 'b', ['a']);
    expect(grab(() => extendRole(g, 'a', ['b'])).message).toContain('Cross inheritance');
  });

  test('preCreateRoles rejects an empty role list', () => {
    expect(grab(() => preCreateRoles({}, [])).message).toContain('Invalid role(s)');
    const g: any = {};
    preCreateRoles(g, ['x']);
    expect(g.x).toEqual({});
  });
});

describe('Mutation kills: validation util edges (round 2)', () => {
  test('normalizeName trims before the empty check (whitespace ⇒ non-empty message)', () => {
    expect(grab(() => normalizeName('   ')).message).toContain('non-empty string');
  });

  test('hasValidNames throws by default (no second arg)', () => {
    expect(grab(() => hasValidNames(['bad name'])).message).toContain('Allowed characters');
  });

  test('normalizeActionPossession: trims + whitespace possession defaults to any', () => {
    expect(grab(() => normalizeActionPossession({ action: '   ' })).message).toContain(
      'Invalid action'
    );
    expect(
      (normalizeActionPossession({ action: 'read', possession: '  own  ' as any }) as any)
        .possession
    ).toBe('own'); // possession trimmed
    expect(
      (normalizeActionPossession({ action: 'read', possession: '   ' as any }) as any).possession
    ).toBe('any'); // whitespace-only ⇒ default any
  });

  test('normalizeQueryInfo: whitespace resource is rejected', () => {
    expect(grab(() => normalizeQueryInfo({ role: 'r', resource: '   ' } as any)).message).toContain(
      'Invalid resource'
    );
  });

  test('normalizeAccessInfo: role/resource messages + null attributes default', () => {
    expect(grab(() => normalizeAccessInfo({ resource: 's' } as any)).message).toContain(
      'Invalid role(s)'
    );
    expect(grab(() => normalizeAccessInfo({ role: 'r' } as any)).message).toContain(
      'Invalid resource(s)'
    );
    expect(
      normalizeAccessInfo({ role: 'r', resource: 's', attributes: null } as any).attributes
    ).toEqual(['*']); // null ⇒ ['*']
  });

  test('resetAttributes: omitted/empty ⇒ ["*"]; explicit list preserved', () => {
    expect(resetAttributes({} as any).attributes).toEqual(['*']);
    expect(resetAttributes({ attributes: [] } as any).attributes).toEqual(['*']);
    expect(resetAttributes({ attributes: ['x'] } as any).attributes).toEqual(['x']);
  });
});

describe('Mutation kills: grants normalize/inspect/resolve (round 2)', () => {
  test('normalizeGrant rule-shape fields: attrs default, possession/effect trim+set', () => {
    // normalized internal shape probed dynamically ⇒ typed loosely
    const g1: any = getInspectedGrants({ u: { d: { read: [{}] } } });
    expect(g1.u.d.read[0].attributes).toEqual(['*']); // omitted attrs ⇒ ['*']
    expect(g1.u.d.read[0].possession).toBe('any'); // omitted possession ⇒ 'any'
    const g2: any = getInspectedGrants({ u: { d: { read: [{ possession: '  own  ' as any }] } } });
    expect(g2.u.d.read[0].possession).toBe('own'); // trimmed + set
    const g3: any = getInspectedGrants({
      u: { d: { read: [{ effect: 'deny', attributes: ['s'] }] } }
    });
    expect(g3.u.d.read[0].effect).toBe('deny');
    const g4: any = getInspectedGrants({
      u: { d: { read: [{ effect: 'grant', attributes: ['s'] }] } }
    });
    expect(g4.u.d.read[0].effect).toBeUndefined(); // only 'deny' is stored
  });

  test('getResources / getActions skip the $extend key (not a resource/action)', () => {
    const g = getInspectedGrants({
      editor: { doc: { read: [{ attributes: ['*'] }] } },
      admin: { $extend: ['editor'] }
    });
    expect(getResources(g)).toEqual(['doc']); // admin.$extend excluded
    expect(getActions(g)).toEqual(['read']);
  });

  test('ownership unverifiable: checks:false ⇒ allowed even with one side missing', () => {
    const ac = new AccessControl({}, { policy: { ownerField: 'o', strict: { checks: false } } });
    ac.grant('u').readOwn('doc', ['*']);
    // record present (owner=1) but no user.id ⇒ ownerId set, userId undefined.
    // with checks off the `own` rule applies (kills the && vs || mutation).
    expect(ac.can('u', { doc: { o: 1 } }).readOwn('doc').granted).toBe(true);
  });

  test('access event reason reflects the denial cause', () => {
    const ac = new AccessControl({}, { policy: { ownerField: 'o' } });
    ac.grant('u').readAny('post', ['*']);
    ac.grant('u').where('$.x == 1').updateAny('post', ['*']);
    ac.grant('u').readOwn('doc', ['*']);
    let reason: unknown = 'unset';
    ac.on('access', (e: any) => {
      reason = e.reason;
    });
    ac.can('u').readAny('post').granted; // granted ⇒ no reason
    expect(reason).toBeUndefined();
    ac.can('u').readAny('ghost').granted; // no candidate ⇒ no_grant
    expect(reason).toBe('no_grant');
    ac.can('u', { x: 2 }).updateAny('post').granted; // condition fails
    expect(reason).toBe('condition_failed');
    ac.can('u', { doc: { o: 2 }, user: { id: 1 } }).readOwn('doc').granted; // ownership fails
    expect(reason).toBe('ownership_failed');
  });
});

describe('Mutation kills: notation & generic utils', () => {
  test('filter returns {} for empty/invalid attrs; keeps matched otherwise', () => {
    expect(filter({ a: 1, b: 2 }, ['a'])).toEqual({ a: 1 });
    expect(filter({ a: 1 }, [])).toEqual({});
    expect(filter({ a: 1 }, null as any)).toEqual({});
  });

  test('impliedStar trims before testing the negation prefix', () => {
    expect(impliedStar([' !x'])).toEqual(['*', ' !x']); // leading space, still all-negated
    expect(impliedStar(['x', '!y'])).toEqual(['x', '!y']); // a positive ⇒ unchanged
    expect(impliedStar([])).toEqual([]);
  });

  test('deepFreeze passes primitives/null through; freezes nested objects', () => {
    expect(deepFreeze(null)).toBe(null); // no early-return ⇒ would throw
    expect(deepFreeze(5 as any)).toBe(5);
    const o: any = { a: { b: 1 }, list: [{ c: 2 }] };
    deepFreeze(o);
    expect(Object.isFrozen(o.a)).toBe(true);
    expect(Object.isFrozen(o.list[0])).toBe(true);
  });
});

describe('Mutation kills: AccessControl & Access edges (round 2)', () => {
  test('grant/deny reject an explicit undefined role', () => {
    expect(grab(() => new AccessControl().grant(undefined as any)).message).toContain('undefined');
    expect(grab(() => new AccessControl().deny(undefined as any)).message).toContain('undefined');
  });

  test('a fresh instance is not locked', () => {
    expect(new AccessControl().isLocked).toBe(false);
  });

  test('removeResources removes only the named resource(s)', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('p', ['*']).grant('u').readAny('q', ['*']);
    ac.removeResources('p');
    expect(ac.hasResource('p')).toBe(false);
    expect(ac.hasResource('q')).toBe(true); // kills "always delete"
  });

  test('defineCondition trims the name (key + empty-name guard)', async () => {
    const ac = new AccessControl();
    ac.defineCondition('  myfn  ', () => true); // stored trimmed
    ac.grant('u').where({ fn: 'myfn' }).readAny('p', ['*']);
    expect(await ac.can('u').readAny('p').grantedAsync).toBe(true); // lookup 'myfn' resolves
    expect(grab(() => ac.defineCondition('   ', () => true)).message).toContain(
      'Invalid condition name'
    );
  });

  test('change event: name field + global require / removeGroup / removeRoles details', () => {
    const ac = new AccessControl();
    const log: any[] = [];
    ac.on('change', (e: any) => log.push(e));
    ac.setup({ roles: { admins: ['admin'] } });
    ac.grant('admins/admin').readAny('post', ['*']);
    ac.require('$.env == prod');
    ac.removeGroup('admins');
    ac.removeRoles('admins/admin');
    expect(log.every((e) => e.name === 'change')).toBe(true);
    const detail = (t: string) => log.find((e) => e.type === t)?.detail;
    expect(detail('require')).toMatchObject({ scope: 'global' });
    expect(detail('remove')).toBeDefined();
    const removes = log.filter((e) => e.type === 'remove').map((e) => e.detail);
    expect(removes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ group: 'admins' }),
        expect.objectContaining({ roles: ['admins/admin'] })
      ])
    );
  });

  test('Access object-form constructor: empty object + invalid type + commit/change', () => {
    const ac = new AccessControl();
    expect(grab(() => ac.grant({} as any)).message).toContain('Invalid IAccessInfo');
    expect(grab(() => ac.grant(123 as any)).message).toContain('Invalid role(s)');
    const details: any[] = [];
    ac.on('change', (e: any) => details.push(e.detail));
    ac.grant({ role: 'r', resource: 's', action: 'read:any', attributes: ['*'] } as any);
    expect(details[0]).toMatchObject({ role: 'r', resource: 's', action: 'read:any' });
    expect(ac.can('r').readAny('s').granted).toBe(true);
  });

  test('Access#resource validates names and allows qualified group/resource', () => {
    const ac = new AccessControl();
    expect(grab(() => ac.grant('u').resource('bad name')).message).toContain('Allowed characters');
    expect(() => ac.grant('u').resource('cat/res')).not.toThrow(); // qualified allowed
  });
});

describe('Mutation kills: grants null-arms, messages & serialization (round 3)', () => {
  test('rule shape: explicit null attributes/possession/effect/condition are tolerated', () => {
    // null attributes ⇒ ['*'] (kills `=== null` arm)
    expect(
      (getInspectedGrants({ u: { d: { read: [{ attributes: null }] } } } as any) as any).u.d.read[0]
        .attributes
    ).toEqual(['*']);
    // null possession ⇒ default 'any' (not validated as "null")
    expect(
      (
        getInspectedGrants({
          u: { d: { read: [{ possession: null, attributes: ['*'] }] } }
        } as any) as any
      ).u.d.read[0].possession
    ).toBe('any');
    // null effect ⇒ no effect set (not validated)
    expect(
      (
        getInspectedGrants({
          u: { d: { read: [{ effect: null, attributes: ['*'] }] } }
        } as any) as any
      ).u.d.read[0].effect
    ).toBeUndefined();
    // null condition ⇒ no compile attempt
    expect(() =>
      getInspectedGrants({ u: { d: { read: [{ condition: null, attributes: ['*'] }] } } } as any)
    ).not.toThrow();
  });

  test('invalid resource definition + invalid rules array carry the right message/field', () => {
    expect(grab(() => getInspectedGrants({ u: { d: 'nope' } } as any)).message).toContain(
      'Invalid resource definition'
    );
    const e = grab(() => getInspectedGrants({ u: { d: { read: 'x' } } } as any));
    expect(e.message).toContain('expected an array');
    expect(e.action).toBe('read');
  });

  test('flat list tolerates null items and qualified $extend-row roles', () => {
    const ac = new AccessControl([
      null as any,
      { role: 'editor', resource: 'doc', action: 'read:any', attributes: ['*'] },
      { role: 'admins/admin', $extend: ['editor'] }
    ]);
    expect(ac.can('admins/admin').readAny('doc').granted).toBe(true);
  });

  test('getGrantsList serializes rules, conditions, deny effect and $extend rows', () => {
    const ac = new AccessControl();
    ac.grant('editor').readAny('doc', ['*']);
    ac.grant('editor').where('$.x == 1').updateAny('doc', ['*']);
    ac.deny('editor').deleteAny('doc');
    ac.grant('admin').readAny('doc', ['*']);
    ac.extendRole('admin', 'editor');

    const rows = ac.getGrantsList();
    const cond = rows.find((r: any) => r.action === 'update');
    expect(cond?.condition).toEqual(['$.x', '==', 1]); // condition only when present
    const del = rows.find((r: any) => r.action === 'delete');
    expect(del?.effect).toBe('deny'); // deny effect serialized
    const ext = rows.find((r: any) => (r as any).$extend);
    expect(ext).toMatchObject({ role: 'admin', $extend: ['editor'] });
    const read = rows.find((r: any) => r.action === 'read' && r.role === 'editor');
    expect(read).not.toHaveProperty('condition'); // no condition key when absent

    // round-trips: rebuilding from rows reproduces behavior
    const ac2 = new AccessControl(rows);
    expect(ac2.can('admin').readAny('doc').granted).toBe(true);
    expect(ac2.can('editor', { x: 1 }).updateAny('doc').granted).toBe(true);
    expect(ac2.can('editor', { x: 2 }).updateAny('doc').granted).toBe(false);
  });
});

describe('Mutation kills: assorted string/operator edges (round 3)', () => {
  test('roles: non-existent extender message joins multiple names with ", "', () => {
    // names are redacted from the message by default; the static reason remains
    // and the joined names travel in err.role
    const e = grab(() => extendRole({ a: {} } as any, 'a', ['g1', 'g2']));
    expect(e.message).toContain('Cannot inherit non-existent role(s)');
    expect(e.role).toEqual(['g1', 'g2']);
  });

  test('setup rejects a non-object vocabulary', () => {
    expect(grab(() => new AccessControl().setup('nope' as any)).message).toContain(
      'Invalid setup vocabulary'
    );
  });

  test('Access change event type is grant vs deny', () => {
    const ac = new AccessControl();
    const types: string[] = [];
    ac.on('change', (e: any) => types.push(e.type));
    ac.grant({ role: 'r', resource: 's', action: 'read:any', attributes: ['*'] } as any);
    ac.deny({ role: 'r', resource: 's', action: 'delete:any' } as any);
    expect(types).toEqual(['grant', 'deny']);
  });

  test('compiler: multi-digit fraction stays numeric; quoted literal LHS with space', () => {
    expect(compileCondition('$.x == 1.25')).toEqual(['$.x', '==', 1.25]); // \d+ fraction
    // a quoted token with an internal space must remain a single token (kills the
    // quote-detection char literals in the tokenizer)
    expect(compileCondition('"a b" == $.x')).toEqual(['a b', '==', '$.x']);
    expect(compileCondition("'a b' == $.x")).toEqual(['a b', '==', '$.x']);
  });

  test('empty-quote literal collapses to the empty string (>=2 length guard)', () => {
    expect(compileCondition('$.s == ""')).toEqual(['$.s', '==', '']);
    expect(evaluateCondition(['$.s', '==', ''], { s: '' })).toBe(true);
  });
});

describe('Mutation kills: deriveNow month table + async reasons (round 4)', () => {
  test('$.now.date derives the correct month number for every month', () => {
    // $.now.date is built from MONTHS.indexOf(monthName)+1; a wrong/blank entry
    // shifts the month number, so each month pins one MONTHS literal.
    for (let m = 0; m < 12; m++) {
      const now = new Date(Date.UTC(2021, m, 15, 12, 0, 0));
      const mm = String(m + 1).padStart(2, '0');
      expect(ev(`$.now.date == 2021-${mm}-15`, { now, tz: 'UTC' })).toBe(true);
    }
  });

  test('async resolution reason: require_failed and condition_failed', async () => {
    const ac = new AccessControl();
    ac.defineCondition('no', () => false);
    ac.grant('u').readAny('post', ['*']);
    ac.grant('u').where({ fn: 'no' }).updateAny('post', ['*']);
    let reason: unknown = 'unset';
    ac.on('access', (e: any) => {
      reason = e.reason;
    });

    // a global require with a failing custom fn ⇒ require_failed (async path)
    ac.require({ fn: 'no' });
    await ac.can('u').readAny('post').grantedAsync;
    expect(reason).toBe('require_failed');

    // drop the gate; the conditional grant's fn fails ⇒ condition_failed
    const ac2 = new AccessControl();
    ac2.defineCondition('no', () => false);
    ac2.grant('u').where({ fn: 'no' }).updateAny('post', ['*']);
    let reason2: unknown = 'unset';
    ac2.on('access', (e: any) => {
      reason2 = e.reason;
    });
    await ac2.can('u').updateAny('post').grantedAsync;
    expect(reason2).toBe('condition_failed');
  });

  test('async grants: a passing custom-fn condition grants access', async () => {
    const ac = new AccessControl();
    ac.defineCondition('ok', (ctx: any) => ctx.flag === true);
    ac.grant('u').where({ fn: 'ok' }).readAny('post', ['*']);
    expect(await ac.can('u', { flag: true }).readAny('post').grantedAsync).toBe(true);
    expect(await ac.can('u', { flag: false }).readAny('post').grantedAsync).toBe(false);
  });
});

describe('Mutation kills: error codes, redaction & detail() (round 5)', () => {
  test('detail() redacts when safe, formats string vs non-string when verbose', () => {
    expect(detail(true, 'abc')).toBe(''); // safe ⇒ empty
    expect(detail(false, 'abc')).toBe(' Got: "abc".'); // string branch
    expect(detail(false, [1, 2])).toBe(' Got: [1,2].'); // non-string ⇒ JSON
    expect(detail(false, 42)).toBe(' Got: 42.');
  });

  test('normalizeName: codes + safe/verbose messages', () => {
    expect(grab(() => normalizeName('')).code).toBe(ErrorCode.INVALID_NAME);
    expect(grab(() => normalizeName('a/b/c', true)).code).toBe(ErrorCode.INVALID_NAME);
    expect(grab(() => normalizeName('_/x', true)).code).toBe(ErrorCode.RESERVED_NAME);
    expect(grab(() => normalizeName('grp/__proto__', true)).code).toBe(ErrorCode.RESERVED_NAME);
    expect(grab(() => normalizeName('__proto__')).code).toBe(ErrorCode.RESERVED_NAME);
    // safe (default) hides the value; verbose shows it
    expect(grab(() => normalizeName('bad name')).message).not.toContain('bad name');
    expect(grab(() => normalizeName('bad name', false, VERBOSE)).message).toContain('bad name');
    expect(grab(() => normalizeName('a/b/c', true, VERBOSE)).message).toContain('a/b/c');
    expect(grab(() => normalizeName('_/x', true, VERBOSE)).message).toContain('_/x');
    expect(grab(() => normalizeName('__proto__', false, VERBOSE)).message).toContain('__proto__');
  });

  test('normalizeActionPossession / query / access: codes + verbose', () => {
    expect(grab(() => normalizeActionPossession({ action: '' })).code).toBe(
      ErrorCode.INVALID_ACTION
    );
    expect(
      grab(() => normalizeActionPossession({ action: 'read', possession: 'x' as any })).code
    ).toBe(ErrorCode.INVALID_ACTION);
    expect(
      grab(() => normalizeActionPossession({ action: 'read', possession: 'x' as any }, VERBOSE))
        .message
    ).toContain('x');
    expect(grab(() => normalizeQueryInfo('x' as any)).code).toBe(ErrorCode.INVALID_QUERY);
    expect(grab(() => normalizeQueryInfo('x' as any, VERBOSE)).message).toContain('string');
    expect(grab(() => normalizeQueryInfo({ role: [] } as any)).code).toBe(ErrorCode.INVALID_NAME);
    expect(grab(() => normalizeQueryInfo({ role: 'r', resource: '' } as any)).code).toBe(
      ErrorCode.INVALID_NAME
    );
    expect(
      grab(() => normalizeQueryInfo({ role: 'r', resource: '  ' } as any, VERBOSE)).message
    ).toContain('Got:');
    expect(grab(() => normalizeAccessInfo('x' as any)).code).toBe(ErrorCode.INVALID_GRANT);
    expect(grab(() => normalizeAccessInfo({ resource: 's' } as any)).code).toBe(
      ErrorCode.INVALID_NAME
    );
    expect(grab(() => normalizeAccessInfo({ role: 'r' } as any)).code).toBe(ErrorCode.INVALID_NAME);
    expect(grab(() => normalizeAccessInfo({ role: [] } as any, false, VERBOSE)).message).toContain(
      'Got:'
    );
  });

  test('roles util: codes + safe/verbose messages', () => {
    expect(grab(() => getRoleHierarchyOf({} as any, 'ghost')).code).toBe(ErrorCode.ROLE_NOT_FOUND);
    expect(grab(() => getRoleHierarchyOf({} as any, 'ghost', VERBOSE)).message).toContain('ghost');
    const selfG = { a: { $extend: ['a'] } } as any;
    expect(grab(() => getRoleHierarchyOf(selfG, 'a')).code).toBe(ErrorCode.INVALID_INHERITANCE);
    expect(grab(() => getRoleHierarchyOf(selfG, 'a', VERBOSE)).message).toContain('a');

    expect(grab(() => extendRole({ a: {} } as any, 'a', ['ghost'])).code).toBe(
      ErrorCode.INVALID_INHERITANCE
    );
    expect(grab(() => extendRole({ a: {} } as any, 'a', ['g1', 'g2'], VERBOSE)).message).toContain(
      'g1, g2'
    );
    expect(grab(() => extendRole({ b: {} } as any, 'a', ['b'])).code).toBe(
      ErrorCode.ROLE_NOT_FOUND
    );
    expect(grab(() => extendRole({ a: {} } as any, 'a', ['a'])).code).toBe(
      ErrorCode.INVALID_INHERITANCE
    );
    // cross inheritance
    const g: any = { a: {}, b: {} };
    extendRole(g, 'b', ['a']);
    const cross = grab(() => extendRole(g, 'a', ['b']));
    expect(cross.code).toBe(ErrorCode.INVALID_INHERITANCE);
    const g2: any = { a: {}, b: {} };
    extendRole(g2, 'b', ['a']);
    expect(grab(() => extendRole(g2, 'a', ['b'], VERBOSE)).message).toContain('b');
    expect(grab(() => preCreateRoles({}, [])).code).toBe(ErrorCode.INVALID_NAME);
  });

  test('grants util: codes + verbose', () => {
    expect(grab(() => getInspectedGrants(42)).code).toBe(ErrorCode.INVALID_GRANT);
    expect(grab(() => getInspectedGrants({ admin: 'x' })).code).toBe(ErrorCode.INVALID_GRANT);
    expect(grab(() => getInspectedGrants({ admin: 'x' }, '$', VERBOSE)).message).toContain('admin');
    expect(grab(() => getInspectedGrants({ u: { d: { read: 'x' } } })).code).toBe(
      ErrorCode.INVALID_GRANT
    );
    expect(grab(() => getInspectedGrants({ u: { d: { read: [{ possession: 'x' }] } } })).code).toBe(
      ErrorCode.INVALID_ACTION
    );
    expect(
      grab(() => getInspectedGrants({ u: { d: { read: [{ attributes: [''] }] } } })).code
    ).toBe(ErrorCode.INVALID_GRANT);
  });
});
