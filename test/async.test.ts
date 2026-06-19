/**
 *  Test Suite: async checks & custom condition functions (P8, §5.5/§5.6.4).
 *  defineCondition() + { fn, args }; grantedAsync / checkAsync; sync .granted
 *  throws (asyncRequired) when an applicable rule carries a custom fn.
 */

import { AccessControl } from '../src/index.js';
import { helper } from './helper.js';

describe('Test Suite: async checks (P8)', () => {
  test('sync .granted throws on a custom { fn }; grantedAsync resolves', async () => {
    const ac = new AccessControl();
    ac.defineCondition('vip', (ctx: any) => ctx.user?.vip === true);
    ac.grant('user').where({ fn: 'vip' }).readAny('lounge', ['*']);

    // sync path refuses (asyncRequired)
    helper.expectACError(() => ac.can('user', { user: { vip: true } }).readAny('lounge').granted);

    // async path evaluates the fn
    expect(await ac.can('user', { user: { vip: true } }).readAny('lounge').grantedAsync).toBe(true);
    expect(await ac.can('user', { user: { vip: false } }).readAny('lounge').grantedAsync).toBe(
      false
    );
  });

  test('async fn (returns a Promise) with args', async () => {
    const ac = new AccessControl();
    ac.defineCondition('ipAllowed', async (ctx: any, args: any) =>
      Promise.resolve((args.allow as string[]).includes(ctx.ip))
    );
    ac.grant('admin')
      .where({ fn: 'ipAllowed', args: { allow: ['10.0.0.1'] } })
      .readAny('server', ['*']);

    expect(await ac.can('admin', { ip: '10.0.0.1' }).readAny('server').grantedAsync).toBe(true);
    expect(await ac.can('admin', { ip: '8.8.8.8' }).readAny('server').grantedAsync).toBe(false);
  });

  test('checkAsync returns a resolved Permission (sync accessors work after)', async () => {
    const ac = new AccessControl();
    ac.defineCondition('vip', (ctx: any) => ctx.user?.vip === true);
    ac.grant('user').where({ fn: 'vip' }).readAny('lounge', ['*', '!secret']);

    const perm = await ac.checkAsync({
      role: 'user',
      resource: 'lounge',
      action: 'read:any',
      context: { user: { vip: true } }
    });
    expect(perm.granted).toBe(true); // sync, already resolved
    expect(perm.attributes).toEqual(['*', '!secret']);
    expect(perm.filter({ a: 1, secret: 2 })).toEqual({ a: 1 });
  });

  test('grantedAsync also works for fully-declarative checks (no fn)', async () => {
    const ac = new AccessControl();
    ac.grant('user').where('$.env == prod').readAny('post', ['*']);
    expect(await ac.can('user', { env: 'prod' }).readAny('post').grantedAsync).toBe(true);
    expect(await ac.can('user', { env: 'dev' }).readAny('post').grantedAsync).toBe(false);
  });

  test('unknown condition function name rejects on the async path', async () => {
    const ac = new AccessControl();
    ac.grant('user').where({ fn: 'missing' }).readAny('post', ['*']);
    await expect(ac.can('user').readAny('post').grantedAsync).rejects.toThrow(/Unknown condition/);
  });

  test('combinator with a fn: and/or short-circuit on the async path', async () => {
    const ac = new AccessControl();
    let called = 0;
    ac.defineCondition('count', () => {
      called++;
      return true;
    });
    // `or` short-circuits: a true declarative leaf means the fn never runs
    ac.grant('user')
      .where({ or: ['$.env == prod', { fn: 'count' }] })
      .readAny('post', ['*']);
    expect(await ac.can('user', { env: 'prod' }).readAny('post').grantedAsync).toBe(true);
    expect(called).toBe(0);
  });

  test('require() gate with a custom fn uses the async path', async () => {
    const ac = new AccessControl();
    ac.defineCondition('mfa', async (ctx: any) => ctx.mfa === true);
    ac.grant('user').readAny('vault', ['*']);
    ac.require({ fn: 'mfa' });

    // sync refuses because an applicable gate is a custom fn
    helper.expectACError(() => ac.can('user', { mfa: true }).readAny('vault').granted);
    expect(await ac.can('user', { mfa: true }).readAny('vault').grantedAsync).toBe(true);
    expect(await ac.can('user', { mfa: false }).readAny('vault').grantedAsync).toBe(false);
  });

  test('defineCondition validates input and is locked-safe', () => {
    const ac = new AccessControl();
    ac.grant('user').readAny('post', ['*']);
    // @ts-expect-error invalid fn
    helper.expectACError(() => ac.defineCondition('x', 'nope'));
    helper.expectACError(() => ac.defineCondition('', () => true));
    ac.lock();
    helper.expectACError(() => ac.defineCondition('y', () => true));
  });
});
