/**
 *  Test Suite: events & audit hooks (P9, §7.3).
 *  on/once/off; access (audit), change (policy-edit), error; observational +
 *  isolated + zero-overhead when no listener.
 */

import { AccessControl, AccessControlEvent } from '../src/index.js';

describe('Test Suite: events (P9)', () => {
  test('access event fires on every resolved check (granted & denied)', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*', '!secret']);
    const events: any[] = [];
    ac.on('access', (e) => events.push(e));

    ac.can('admin').readAny('post').granted; // granted
    ac.can('admin').deleteAny('post').granted; // denied (no grant)

    expect(events).toHaveLength(2);
    expect(events[0]).toMatchObject({
      name: 'access',
      roles: ['admin'],
      resource: 'post',
      action: 'read',
      possession: 'any',
      granted: true,
      attributes: ['*', '!secret']
    });
    expect(typeof events[0].timestamp).toBe('number');
    expect(events[1]).toMatchObject({ granted: false, reason: 'no_grant' });
  });

  test('access reason: condition_failed / require_failed / ownership_failed', () => {
    const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
    ac.grant('user').where('$.env == prod').readAny('a', ['*']);
    ac.grant('user').readOwn('b', ['*']);
    ac.grant('user').readAny('c', ['*']);
    ac.resource('c').require('$.mfa == true');

    const reasons: Record<string, string | undefined> = {};
    ac.on('access', (e: any) => {
      reasons[e.resource] = e.reason;
    });

    ac.can('user', { env: 'dev' }).readAny('a').granted; // condition fails
    ac.can('user', { user: { id: 1 } }).readOwn('b').granted; // ownership unverifiable
    ac.can('user', { mfa: false }).readAny('c').granted; // require gate fails

    expect(reasons.a).toBe('condition_failed');
    expect(reasons.b).toBe('ownership_failed');
    expect(reasons.c).toBe('require_failed');
  });

  test('access event carries category for a qualified resource', () => {
    const ac = new AccessControl();
    ac.grant('editor').readAny('media', ['*']);
    let evt: any;
    ac.on('access', (e) => {
      evt = e;
    });
    ac.can('editor').readAny('media/photo').granted;
    expect(evt).toMatchObject({ resource: 'media/photo', category: 'media', granted: true });
  });

  test('change event fires on grant/deny/extend/setup/require/remove/reset/lock', () => {
    const ac = new AccessControl();
    const types: string[] = [];
    ac.on(AccessControlEvent.Change, (e: any) => types.push(e.type));

    ac.grant('admin').readAny('post', ['*']); // grant
    ac.deny('admin').deleteAny('post'); // deny
    ac.grant('user').readAny('post', ['*']);
    ac.extendRole('admin', 'user'); // extend
    ac.setup({ roles: ['guest'] }); // setup
    ac.require('$.env == prod'); // require
    ac.removeRoles('user'); // remove
    ac.lock(); // lock

    expect(types).toEqual([
      'grant',
      'deny',
      'grant',
      'extend',
      'setup',
      'require',
      'remove',
      'lock'
    ]);
  });

  test('error event fires when a check throws (e.g. strict unknown role)', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    const errors: any[] = [];
    ac.on('error', (e) => errors.push(e));

    let threw = false;
    try {
      ac.can('ghost').readAny('post').granted; // strict.roles → throws
    } catch {
      threw = true;
    }
    expect(threw).toBe(true);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatchObject({ name: 'error', operation: 'check' });
    expect(errors[0].error).toBeInstanceOf(Error);
  });

  test('once fires a single time; off removes the listener', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    let onceCount = 0;
    let onCount = 0;
    const onListener = () => {
      onCount++;
    };
    ac.once('access', () => {
      onceCount++;
    });
    ac.on('access', onListener);

    ac.can('admin').readAny('post').granted;
    ac.can('admin').readAny('post').granted;
    expect(onceCount).toBe(1);
    expect(onCount).toBe(2);

    ac.off('access', onListener);
    ac.can('admin').readAny('post').granted;
    expect(onCount).toBe(2); // not incremented after off
  });

  test('listeners are observational and isolated (a throwing listener never breaks a check)', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    ac.on('access', () => {
      throw new Error('boom');
    });
    let ok = false;
    ac.on('access', () => {
      ok = true; // sibling still runs
    });
    expect(ac.can('admin').readAny('post').granted).toBe(true); // check unaffected
    expect(ok).toBe(true);
  });

  test('async checks also emit access', async () => {
    const ac = new AccessControl();
    ac.defineCondition('vip', async (ctx: any) => ctx.vip === true);
    ac.grant('user').where({ fn: 'vip' }).readAny('lounge', ['*']);
    const events: any[] = [];
    ac.on('access', (e) => events.push(e));

    await ac.can('user', { vip: true }).readAny('lounge').grantedAsync;
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ resource: 'lounge', granted: true });
  });

  test('off(name) without a listener removes all listeners for that event', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    let count = 0;
    ac.on('access', () => count++);
    ac.on('access', () => count++);
    ac.can('admin').readAny('post').granted;
    expect(count).toBe(2);
    ac.off('access'); // remove ALL access listeners
    ac.can('admin').readAny('post').granted;
    expect(count).toBe(2);
  });

  test('access via check() derives possession from the action string', () => {
    const ac = new AccessControl();
    ac.grant('user').readOwn('doc', ['*']);
    let evt: any;
    ac.on('access', (e) => {
      evt = e;
    });
    ac.check({ role: 'user', resource: 'doc', action: 'read:own' }).granted;
    expect(evt).toMatchObject({ action: 'read', possession: 'own' });
  });

  test('a throwing custom fn surfaces as an error event (wrapped) on the async path', async () => {
    const ac = new AccessControl();
    ac.defineCondition('boom', () => {
      throw new TypeError('kaboom');
    });
    ac.grant('user').where({ fn: 'boom' }).readAny('x', ['*']);
    const errors: any[] = [];
    ac.on('error', (e) => errors.push(e));

    await expect(ac.can('user').readAny('x').grantedAsync).rejects.toThrow();
    expect(errors).toHaveLength(1);
    expect(errors[0].error).toBeInstanceOf(Error);
    expect(errors[0].error.message).toContain('kaboom');
  });

  test('on/once/off are chainable; event names accept the enum', () => {
    const ac = new AccessControl();
    const fn = () => {};
    expect(ac.on(AccessControlEvent.Access, fn)).toBe(ac);
    expect(ac.once(AccessControlEvent.Change, fn)).toBe(ac);
    expect(ac.off(AccessControlEvent.Access, fn)).toBe(ac);
  });
});
