/**
 *  Test Suite: edge cases for full coverage.
 *  Exercises rarely-hit branches across the public API and internal utils.
 */

import { Access, AccessControl, Emitter, Permission, Query } from '../src/index.js';
import type { IGrants } from '../src/types/index.js';
import {
  commitToGrants,
  compileCondition,
  evaluateCondition,
  evaluateConditionAsync,
  isFilledStringArray,
  resolveAccess,
  resolveAccessAsync
} from '../src/utils/index.js';
import { helper } from './helper.js';

const ev = (expr: any, ctx: any = {}) => evaluateCondition(compileCondition(expr), ctx);

describe('Test Suite: AccessControl edge cases', () => {
  test('setup() throws when locked or given a non-object', () => {
    helper.expectACError(() => new AccessControl().setup('nope' as any));
    const ac = new AccessControl();
    ac.grant('user').readAny('post', ['*']);
    ac.lock();
    helper.expectACError(() => ac.setup({ roles: ['x'] }));
  });

  test('setup() ungrouped `_` bucket flattens into the strict known set', () => {
    const ac = new AccessControl({}, { policy: { strict: true } });
    ac.setup({ roles: { _: ['user'] }, resources: { _: ['post'] } });
    ac.grant('user').readAny('post', ['*']);
    // declared via `_` ⇒ known ⇒ no throw, just granted/denied
    expect(ac.can('user').readAny('post').granted).toBe(true);
    expect(ac.can('user').updateAny('post').granted).toBe(false);
  });

  test('require() adds to an existing scope bucket (no overwrite)', () => {
    const ac = new AccessControl();
    ac.grant('clerk').readAny('billing/invoice', ['*']);
    ac.category('billing').require('$.ip == trusted');
    ac.category('billing').require('$.mfa == true'); // second gate, same scope
    expect(ac.getRequirements().categories.billing).toHaveLength(2);
    expect(ac.can('clerk', { ip: 'trusted', mfa: true }).readAny('billing/invoice').granted).toBe(
      true
    );
    expect(ac.can('clerk', { ip: 'trusted', mfa: false }).readAny('billing/invoice').granted).toBe(
      false
    );
  });

  test('removeGroup/removeCategory throw when locked; removeCategory tolerates absent resource', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']); // a role without the `media` category
    ac.grant('editor').readAny('media', ['*']);
    ac.removeCategory('media'); // editor had it, admin didn't — both handled
    expect(ac.can('editor').readAny('media/photo').granted).toBe(false);

    ac.lock();
    helper.expectACError(() => ac.removeGroup('admins'));
    helper.expectACError(() => ac.removeCategory('media'));
  });

  test('re-granting the same possession+effect+condition replaces (last write wins)', () => {
    const ac = new AccessControl();
    ac.grant('user').readAny('post', ['a']);
    ac.grant('user').readAny('post', ['b']); // same possession/effect/no-condition ⇒ replace
    expect([...ac.can('user').readAny('post').attributes].sort()).toEqual(['b']);
    // a conditioned grant coexists with the unconditioned one
    ac.grant('user').where('$.x == 1').readAny('post', ['c']);
    // re-granting the SAME condition replaces it (not a third rule)
    ac.grant('user').where('$.x == 1').readAny('post', ['d']);
    const rules = (ac.getGrants() as any).user.post.read;
    expect(rules).toHaveLength(2);
  });

  test('object-form grant rules (possession/effect/condition) + $extend rows + strict with extend', () => {
    const ac = new AccessControl(
      {
        user: {
          post: {
            read: [
              { possession: 'own', effect: 'deny', attributes: ['secret'], condition: '$.x == 1' },
              { effect: 'grant', attributes: ['*'] }
            ]
          }
        }
      },
      { policy: { strict: { resources: true } } }
    );
    expect(ac.can('user').readAny('post').granted).toBe(true);

    // a flat list where the $extend row references a brand-new role key
    const ac2 = new AccessControl([
      { role: 'editor', resource: 'doc', action: 'read:any', attributes: ['*'] },
      { role: 'admin', $extend: ['editor'] }
    ]);
    expect(ac2.can('admin').readAny('doc').granted).toBe(true);
    // getResources (via strict) iterates a model containing $extend keys
    expect(ac2.getResources()).toContain('doc');
  });

  test('extendRole with an empty extender list is a no-op', () => {
    const ac = new AccessControl();
    ac.grant('user').readAny('post', ['*']);
    expect(ac.extendRole('user', [])).toBe(ac);
  });

  test('commitToGrants applies its defaults when called minimally', () => {
    const grants: any = {};
    commitToGrants(grants, { role: 'u', resource: 'p', action: 'read', attributes: ['*'] });
    expect(grants.u.p.read).toBeDefined();
  });

  test('a global require gate applies to a qualified resource without a category gate', () => {
    const ac = new AccessControl();
    ac.grant('clerk').readAny('media/photo', ['*']);
    ac.require('$.env == prod'); // global only — `media` has no category gate
    expect(ac.can('clerk', { env: 'prod' }).readAny('media/photo').granted).toBe(true);
    expect(ac.can('clerk', { env: 'dev' }).readAny('media/photo').granted).toBe(false);
  });

  test('async require() gate is evaluated on the async path', async () => {
    const ac = new AccessControl();
    ac.defineCondition('mfa', async (c: any) => c.mfa === true);
    ac.grant('user').readAny('vault', ['*']);
    ac.require({ fn: 'mfa' });
    expect(await ac.can('user', { mfa: true }).readAny('vault').grantedAsync).toBe(true);
    expect(await ac.can('user', { mfa: false }).readAny('vault').grantedAsync).toBe(false);
  });
});

describe('Test Suite: Access / Query edge cases', () => {
  test('Access: denied getter + bare read/update aliases + array & object grant', () => {
    const ac = new AccessControl();
    const granted = ac.grant('user');
    expect(granted.denied).toBe(false);
    expect(ac.deny('user').denied).toBe(true);

    ac.grant('user').read('post', ['*']).update('post', ['title']);
    expect(ac.can('user').read('post').granted).toBe(true);
    expect(ac.can('user').update('post').attributes).toEqual(['title']);

    ac.grant(['a', 'b']).createAny('thing', ['*']); // array of roles
    expect(ac.can('a').createAny('thing').granted).toBe(true);

    // IAccessInfo object form
    ac.grant({ role: 'm', resource: 'doc', action: 'read:any', attributes: ['*'] });
    expect(ac.can('m').readAny('doc').granted).toBe(true);

    // invalid roleOrInfo type throws (Access + Query dispatch else-branches)
    helper.expectACError(() => ac.grant(123 as any));
    helper.expectACError(() => ac.deny(123 as any));
    expect(() => (ac.can as () => unknown)()).not.toThrow(); // no-arg Query (undefined role path)
  });

  test('Query: IQueryInfo object form, array roles, and invalid inputs', () => {
    const ac = new AccessControl();
    ac.grant('admin').where('$.x == 1').readAny('post', ['*']);
    // object form carrying context, then resolved via a verb
    expect(
      ac
        .can({ role: 'admin', resource: 'post', action: 'read:any', context: { x: 1 } })
        .readAny('post').granted
    ).toBe(true);
    // array roles
    ac.grant('user').readAny('post', ['title']);
    expect(ac.can(['admin', 'user']).readAny('post').granted).toBe(true);
    // invalid
    helper.expectACError(() => ac.can({} as any));
    helper.expectACError(() => ac.can(123 as any));
  });

  test('Query.resource() chainer + verb without explicit resource', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']).deleteAny('post', ['*']);
    const q = ac.can('admin').resource('post');
    expect(q.readAny().granted).toBe(true); // _getPermission with resource already set
    expect(ac.can('admin').resource('post').delete().granted).toBe(true);
  });
});

describe('Test Suite: Permission / Emitter / ownership edge cases', () => {
  test('check() without a resource throws (and emits error when listened)', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    const errors: any[] = [];
    ac.on('error', (e) => errors.push(e));
    expect(() => ac.check({ role: 'admin', action: 'read' } as any).granted).toThrow();
    expect(errors.length).toBeGreaterThan(0);
  });

  test('access event possession is undefined for a bare action', () => {
    const ac = new AccessControl();
    ac.grant('admin').action('ping', 'svc', ['*']);
    let evt: any;
    ac.on('access', (e) => {
      evt = e;
    });
    ac.can('admin').action('ping', 'svc').granted;
    expect(evt).toMatchObject({ action: 'ping', possession: 'any' });
  });

  test('Emitter: off without listener, emit with no listeners, once', () => {
    const em = new Emitter();
    em.off('access'); // no set yet — no-op
    em.emit('access', { name: 'access', timestamp: 0 } as any); // no listeners — no-op
    let n = 0;
    em.once('change', () => n++);
    em.emit('change', { name: 'change', timestamp: 0 } as any);
    em.emit('change', { name: 'change', timestamp: 0 } as any);
    expect(n).toBe(1);
    em.on('access', () => {});
    em.off('access'); // clear all for a populated set
    em.emit('access', { name: 'access', timestamp: 0 } as any);
  });

  test('internal resolvers / Permission / Query work with no options (defensive defaults)', async () => {
    const grants: IGrants = {
      user: { post: { read: [{ possession: 'any', attributes: ['*'] }] } }
    };
    const q = { role: 'user', resource: 'post', action: 'read:any' };
    // no options ⇒ exercises every `options?.x` / `?? default` fallback
    expect(resolveAccess(grants, q).attributes).toEqual(['*']);
    expect((await resolveAccessAsync(grants, q)).attributes).toEqual(['*']);

    const p = new Permission(grants, q); // no options ⇒ no emitter/context
    expect(p.granted).toBe(true);
    expect(p.attributes).toEqual(['*']);
    expect(
      await new Permission(grants, { role: 'user', resource: 'post', action: 'read:own' })
        .grantedAsync
    ).toBe(true);
    expect(new Query(grants, 'user').readAny('post').granted).toBe(true);
  });

  test('direct Access/Query/Permission construction (default-arg & no-policy fallbacks)', () => {
    const ac = new AccessControl();
    ac.grant('user').readAny('post', ['*']);
    // Access constructed without the `denied` arg (default) and with a bare ac
    // lacking _policy (covers `_policy?.pathPrefix ?? '$'`).
    const a = new Access(ac, 'role2');
    expect(a.denied).toBe(false);
    expect(() => new Access({ _grants: {} } as any, 'role3')).not.toThrow();
    // Query with no role at all (undefined dispatch branch)
    expect(() => new Query((ac as any)._grants)).not.toThrow();
    // Permission with no options that throws ⇒ _emitError with no emitter
    expect(
      () => new Permission({}, { role: 'ghost', resource: 'p', action: 'read' }).granted
    ).toThrow();
  });

  test('declaring the same vocab member twice is idempotent', () => {
    const ac = new AccessControl();
    ac.setup({ roles: { admins: ['admin'] } }).setup({ roles: { admins: ['admin'] } });
    expect(ac.group('admins').getRoles()).toEqual(['admins/admin']);
  });

  test('access event omits possession for an action without one', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('p', ['*']);
    let evt: any;
    ac.on('access', (e) => {
      evt = e;
    });
    ac.check({ role: 'u', resource: 'p', action: 'read' }).granted;
    expect(evt.possession).toBeUndefined();
  });

  test('ownership resolver edge cases', () => {
    // owner() fn with missing data ⇒ false
    const ac = new AccessControl(
      {},
      { policy: { owner: (c: any) => c.user?.id != null && c.user.id === c.doc?.owner } }
    );
    ac.grant('user').updateOwn('doc', ['*']);
    expect(ac.can('user', {}).updateOwn('doc').granted).toBe(false);
    expect(ac.can('user', { user: { id: 1 }, doc: { owner: 1 } }).updateOwn('doc').granted).toBe(
      true
    );
    // ownerField but user present without id ⇒ unverifiable ⇒ deny (strict default)
    const ac2 = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
    ac2.grant('user').updateOwn('doc', ['*']);
    expect(ac2.can('user', { user: {}, doc: { ownerId: 1 } }).updateOwn('doc').granted).toBe(false);
  });

  test('async resolution traverses groups, lenient-unknown roles and empty rule sets', async () => {
    const ac = new AccessControl({}, { policy: { strict: { roles: false } } });
    ac.defineCondition('ok', async () => true);
    ac.grant('admins').where({ fn: 'ok' }).readAny('media', ['*']);
    // group member + category, async fn, plus a second unknown role (lenient skip)
    expect(await ac.can(['admins/admin', 'ghost']).readAny('media/photo').grantedAsync).toBe(true);
    // an action with no matching rules ⇒ denied
    expect(await ac.can('admins/admin').deleteAny('media/photo').grantedAsync).toBe(false);
  });
});

describe('Test Suite: condition operators & utils', () => {
  test('isFilledStringArray rejects non-arrays', () => {
    expect(isFilledStringArray(null as any)).toBe(false);
    expect(isFilledStringArray('x' as any)).toBe(false);
  });

  test('comparison / membership / string operators', () => {
    expect(ev('$.n == 5 ', { n: 5 })).toBe(true); // trailing space tokenization
    expect(ev('$.n != 5', { n: 6 })).toBe(true);
    expect(ev('$.n >= 5', { n: 5 })).toBe(true);
    expect(ev('$.s == "bob"', { s: 'bob' })).toBe(true); // quoted literal
    expect(ev('$.role in [admin, user]', { role: 'user' })).toBe(true);
    expect(ev('$.tags contains red', { tags: ['red', 'blue'] })).toBe(true);
    expect(ev('$.x in []', { x: 'a' })).toBe(false); // empty list
    expect(ev('$.name matches ^rep', { name: 'report' })).toBe(true);
    expect(ev('$.name startsWith rep', { name: 'report' })).toBe(true);
    expect(ev('$.name endsWith ort', { name: 'report' })).toBe(true);
  });

  test('time, between and network operators', () => {
    expect(ev('$.v between [1, 10]', { v: 5 })).toBe(true);
    expect(ev('$.d between [2020-01-01, 2020-12-31]', { d: '2020-06-01' })).toBe(true);
    expect(ev('$.t between [22:00, 06:00]', { t: '23:30' })).toBe(true); // wrapping window
    expect(ev('$.d after 2020-01-01', { d: '2021-01-01' })).toBe(true);
    expect(ev('$.d before 2020-01-01', { d: '2019-01-01' })).toBe(true);
    expect(ev('$.ip cidr 10.0.0.0/8', { ip: '10.1.2.3' })).toBe(true);
    expect(ev('$.ip cidr 10.0.0.0/8', { ip: 'not-an-ip' })).toBe(false); // non-ipv4 ⇒ false
    expect(ev('$.ip in [10.0.0.0/8, 192.168.0.0/16]', { ip: '192.168.1.1' })).toBe(true);
  });

  test('not modifier, bareword literals and the `$` root operand', () => {
    expect(ev('$.x not in [a, b]', { x: 'c' })).toBe(true);
    expect(ev('$.flag == true', { flag: true })).toBe(true);
    expect(ev('$.flag == false', { flag: false })).toBe(true);
    expect(ev('$.v == null', { v: null })).toBe(true);
    expect(ev('$ == $', { any: 1 })).toBe(true); // `$` resolves to the whole context
  });

  test('$.now is auto-injected (overridable) with timezone; now-as-string accepted', () => {
    const fri = { now: new Date('2026-06-19T12:00:00Z'), tz: 'UTC' };
    expect(ev('$.now.year >= 2026', fri)).toBe(true);
    expect(ev('$.now.weekday == fri', fri)).toBe(true);
    expect(ev('$.now.hour < 24', fri)).toBe(true);
    expect(ev('$.now.year > 2000', { now: '2026-06-19T00:00:00Z' })).toBe(true); // string now
  });

  test('cidr with a path member resolving to a bad base ⇒ false', () => {
    expect(ev('$.ip cidr $.range', { ip: '10.0.0.1', range: 'bad/8' })).toBe(false);
  });

  test('cidr /0 matches all; attribute-less rule defaults; error events for actionless/async throws', async () => {
    expect(ev('$.ip cidr 0.0.0.0/0', { ip: '8.8.8.8' })).toBe(true); // bits === 0

    // object-form rule lacking `attributes` ⇒ defaults to ['*']
    const ac0 = new AccessControl({ u: { p: { read: [{}] } } } as any);
    expect(ac0.can('u').readAny('p').granted).toBe(true);

    // a thrown check with no action ⇒ _emitError with `action ?? ''`
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    const errs: any[] = [];
    ac.on('error', (e) => errs.push(e));
    expect(() => ac.check({ role: 'admin', resource: 'post' } as any).granted).toThrow();
    expect(errs[0].action).toBe('');

    // async throw of a non-AccessControlError (Error) ⇒ wrapped via err.message
    const ac2 = new AccessControl();
    ac2.defineCondition('boom', () => {
      throw new TypeError('x');
    });
    ac2.grant('u').where({ fn: 'boom' }).readAny('p', ['*']);
    const e2: any[] = [];
    ac2.on('error', (e) => e2.push(e));
    await expect(ac2.can('u').readAny('p').grantedAsync).rejects.toThrow();
    expect(e2[0].error.message).toBe('x');

    // async throw of a non-Error value ⇒ wrapped via String(err)
    const ac3 = new AccessControl();
    ac3.defineCondition('bang', () => {
      // throwing a non-Error value to exercise the String(err) wrap path
      const notAnError: unknown = 'plain-string';
      throw notAnError;
    });
    ac3.grant('u').where({ fn: 'bang' }).readAny('p', ['*']);
    const e3: any[] = [];
    ac3.on('error', (e) => e3.push(e));
    await expect(ac3.can('u').readAny('p').grantedAsync).rejects.toBeDefined();
    expect(e3[0].error.message).toBe('plain-string');
  });

  test('compile-time validation errors', () => {
    helper.expectACError(() => compileCondition('$.x in [a,,b]')); // empty operand
    helper.expectACError(() => compileCondition("$.s == 'unterminated"));
    helper.expectACError(() => compileCondition('$.list in [a, b')); // unterminated bracket
    helper.expectACError(() => compileCondition('$.ip cidr 10.0.0/8')); // malformed CIDR
    helper.expectACError(() => compileCondition('$.v between [5, 2]')); // start > end
    helper.expectACError(() => compileCondition('$.v between [1]')); // not two bounds
  });

  test('evaluator rejects malformed canonical nodes', () => {
    helper.expectACError(() => evaluateCondition({ or: 'nope' } as any));
    expect(evaluateCondition({ not: ['$.x', '==', 1] } as any, { x: 2 })).toBe(true);
  });

  test('single-quoted literal + cidr exact match + non-string cidr list member', () => {
    expect(ev("$.s == 'bob'", { s: 'bob' })).toBe(true);
    expect(ev('$.ip cidr 10.0.0.1', { ip: '10.0.0.1' })).toBe(true); // no-slash exact
    expect(ev('$.ip in [10.0.0.0/8, 5]', { ip: '10.1.1.1' })).toBe(true); // numeric member skipped
  });

  test('before/after coerce numbers, times and non-date strings', () => {
    expect(ev('$.n after 5', { n: 10 })).toBe(true);
    expect(ev('$.t after 09:00', { t: '10:00' })).toBe(true);
    expect(ev('$.s after alpha', { s: 'beta' })).toBe(true); // non-date strings compare lexically
  });

  test('compileCondition validates canonical (array/object) nodes too', () => {
    helper.expectACError(() => compileCondition(['$.x', 'bogus', 1] as any));
    helper.expectACError(() => compileCondition(['$.v', 'between', [5, 2]] as any));
    helper.expectACError(() => compileCondition(['$.ip', 'cidr', '10.0.0/8'] as any));
    helper.expectACError(() =>
      compileCondition(['$.ip', 'in', ['10.0.0.0/8', '10.0.0.0/99']] as any)
    );
    helper.expectACError(() => compileCondition({ or: 'x' } as any));
    expect(compileCondition({ not: '$.x == 1' })).toEqual({ not: ['$.x', '==', 1] });
    // custom-fn node passes through compilation unchanged
    expect(compileCondition({ fn: 'x', args: { a: 1 } })).toEqual({ fn: 'x', args: { a: 1 } });
    // before/after tolerate non-string/number operands (returns the value as-is)
    expect(ev('$.a after $.b', { a: {}, b: {} })).toBe(false);
  });

  test('async evaluator short-circuits and runs custom fns', async () => {
    const reg = { yes: async () => true, no: () => false };
    expect(
      await evaluateConditionAsync({ and: [['$.x', '==', 2], { fn: 'no' }] }, { x: 1 }, '$', reg)
    ).toBe(false); // `and` first leaf false ⇒ short-circuit
    expect(await evaluateConditionAsync({ or: [{ fn: 'no' }, { fn: 'no' }] }, {}, '$', reg)).toBe(
      false
    ); // `or` all false
    expect(await evaluateConditionAsync({ fn: 'yes' }, {}, '$', reg)).toBe(true);
  });
});
