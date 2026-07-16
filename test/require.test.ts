/**
 *  Test Suite: require() mandatory restriction gates (P7, §7.2).
 *  `granted = (a grant matches) AND (every applicable require-gate passes)`.
 *  require() can only restrict — never grant.
 */

import { AccessControl } from '../src/index.js';
import { helper } from './helper.js';

describe('Test Suite: require() gates (P7)', () => {
  test('global gate must pass even when a grant matches', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    ac.require('$.env == prod');
    expect(ac.can('admin', { env: 'prod' }).readAny('post').granted).toBe(true);
    expect(ac.can('admin', { env: 'dev' }).readAny('post').granted).toBe(false);
  });

  test('a gate fails closed when its context property is missing or absent', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    ac.require('$.env == prod');
    // property omitted from a supplied context → `$.env` resolves to undefined
    // → `undefined === 'prod'` is false → gate fails → denied.
    expect(ac.can('admin', { user: 'x' }).readAny('post').granted).toBe(false);
    // no context at all behaves identically.
    expect(ac.can('admin').readAny('post').granted).toBe(false);
    // and the denial carries the gate-specific reason.
    let reason = '';
    ac.on('access', (e: any) => {
      reason = e.reason ?? '';
    });
    ac.can('admin', {}).readAny('post');
    expect(reason).toBe('require_failed');
  });

  test('a negated gate operator fails OPEN on a missing property (sharp edge)', () => {
    // `==` denies on absence (fail-closed); negative operators do NOT. With the
    // property absent, `undefined !== 'dev'` is true → the gate passes. Prefer the
    // positive assertion form (`$.env == prod`) so absence denies.
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    ac.require('$.env != dev');
    expect(ac.can('admin', {}).readAny('post').granted).toBe(true); // ⚠ passes
    expect(ac.can('admin', { env: 'dev' }).readAny('post').granted).toBe(false);
  });

  test('require can only restrict: a passing gate never grants on its own', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('other', ['*']); // admin is a known role…
    ac.require('$.env == prod'); // gate passes, but no grant exists for `post`
    expect(ac.can('admin', { env: 'prod' }).readAny('post').granted).toBe(false);
  });

  test('category gate applies only to resources in that category', () => {
    const ac = new AccessControl();
    ac.grant('clerk').readAny('billing/invoice', ['*']);
    ac.grant('clerk').readAny('media/photo', ['*']);
    ac.category('billing').require('$.ip == trusted');

    // billing resource is gated
    expect(ac.can('clerk', { ip: 'trusted' }).readAny('billing/invoice').granted).toBe(true);
    expect(ac.can('clerk', { ip: 'other' }).readAny('billing/invoice').granted).toBe(false);
    // a resource in a different category is unaffected
    expect(ac.can('clerk', { ip: 'other' }).readAny('media/photo').granted).toBe(true);
  });

  test('resource gate applies only to that resource', () => {
    const ac = new AccessControl();
    ac.grant('clerk').readAny('billing/invoice', ['*']);
    ac.grant('clerk').readAny('billing/report', ['*']);
    ac.resource('billing/invoice').require('$.mfa == true');

    expect(ac.can('clerk', { mfa: true }).readAny('billing/invoice').granted).toBe(true);
    expect(ac.can('clerk', { mfa: false }).readAny('billing/invoice').granted).toBe(false);
    // sibling resource (same category) is not resource-gated
    expect(ac.can('clerk', { mfa: false }).readAny('billing/report').granted).toBe(true);
  });

  test('all applicable gates (global + category + resource) must pass', () => {
    const ac = new AccessControl();
    ac.grant('clerk').readAny('billing/invoice', ['*']);
    ac.require('$.env == prod');
    ac.category('billing').require('$.ip == trusted');
    ac.resource('billing/invoice').require('$.mfa == true');

    const ok = ac.can('clerk', { env: 'prod', ip: 'trusted', mfa: true });
    expect(ok.readAny('billing/invoice').granted).toBe(true);
    // any single failing gate denies
    expect(
      ac.can('clerk', { env: 'dev', ip: 'trusted', mfa: true }).readAny('billing/invoice').granted
    ).toBe(false);
    expect(
      ac.can('clerk', { env: 'prod', ip: 'bad', mfa: true }).readAny('billing/invoice').granted
    ).toBe(false);
    expect(
      ac.can('clerk', { env: 'prod', ip: 'trusted', mfa: false }).readAny('billing/invoice').granted
    ).toBe(false);
  });

  test('gates use the same condition engine as .where() (operators, $.now)', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    ac.require('$.order.value < 1000');
    expect(ac.can('admin', { order: { value: 500 } }).readAny('post').granted).toBe(true);
    expect(ac.can('admin', { order: { value: 5000 } }).readAny('post').granted).toBe(false);
  });

  test('getRequirements() returns a copy by scope', () => {
    const ac = new AccessControl();
    ac.require('$.env == prod');
    ac.category('billing').require('$.ip == trusted');
    ac.resource('billing/invoice').require('$.mfa == true');
    const reqs = ac.getRequirements();
    expect(reqs.global).toHaveLength(1);
    expect(reqs.categories.billing).toHaveLength(1);
    expect(reqs.resources['billing/invoice']).toHaveLength(1);
    // mutating the copy does not affect the engine
    reqs.global.push(['x', '==', 'y']);
    expect(ac.getRequirements().global).toHaveLength(1);
  });

  test('require() and scoped requires are chainable and locked-safe', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']); // non-empty grants so lock() is allowed
    expect(ac.require('$.env == prod')).toBe(ac);
    expect(ac.category('billing').require('$.ip == trusted')).toBe(ac);
    expect(ac.resource('billing/invoice').require('$.mfa == true')).toBe(ac);
    ac.lock();
    helper.expectACError(() => ac.require('$.env == prod'));
    helper.expectACError(() => ac.category('billing').require('$.ip == trusted'));
    helper.expectACError(() => ac.resource('billing/invoice').require('$.mfa == true'));
  });

  test('require gate works through check() as well as can()', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    ac.require('$.env == prod');
    expect(
      ac.check({ role: 'admin', resource: 'post', action: 'read:any', context: { env: 'prod' } })
        .granted
    ).toBe(true);
    expect(
      ac.check({ role: 'admin', resource: 'post', action: 'read:any', context: { env: 'dev' } })
        .granted
    ).toBe(false);
  });
});

describe('during — temporal require() gates', () => {
  const BH = 'T0900:1800 E1:5'; // Mon–Fri, 09:00–18:00
  const monMorning = { now: '2026-07-20T10:00:00Z', tz: 'UTC' };
  const satMorning = { now: '2026-07-18T10:00:00Z', tz: 'UTC' };

  test('a global during gate time-boxes every check', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    ac.require(`$.now during "${BH}"`);
    expect(ac.can('admin', monMorning).readAny('post').granted).toBe(true);
    expect(ac.can('admin', satMorning).readAny('post').granted).toBe(false);
  });

  test('category and resource during gates apply to their scope only', () => {
    const ac = new AccessControl();
    ac.grant('user').readAny('billing/invoice', ['*']).readAny('blog/post', ['*']);
    ac.category('billing').require(`$.now during "${BH}"`);
    // billing is time-boxed; blog is not
    expect(ac.can('user', satMorning).readAny('billing/invoice').granted).toBe(false);
    expect(ac.can('user', monMorning).readAny('billing/invoice').granted).toBe(true);
    expect(ac.can('user', satMorning).readAny('blog/post').granted).toBe(true);

    const ac2 = new AccessControl();
    ac2.grant('user').readAny('report', ['*']);
    ac2.resource('report').require(`$.now during "${BH}"`);
    expect(ac2.can('user', satMorning).readAny('report').granted).toBe(false);
    expect(ac2.can('user', monMorning).readAny('report').granted).toBe(true);
  });

  test('a failed during gate reports reason "require_failed"', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    ac.require(`$.now during "${BH}"`);
    let reason = '';
    ac.on('access', (e: any) => {
      reason = e.reason ?? '';
    });
    ac.can('admin', satMorning).readAny('post');
    expect(reason).toBe('require_failed');
  });

  test('async path: checkAsync honors during gates', async () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    ac.require(`$.now during "${BH}"`);
    const q = (context: any) =>
      ac.checkAsync({ role: 'admin', resource: 'post', action: 'read:any', context });
    expect((await q(monMorning)).granted).toBe(true);
    expect((await q(satMorning)).granted).toBe(false);
  });

  test('an invalid during gate expression throws at require() time', () => {
    const ac = new AccessControl();
    helper.expectACError(() => ac.require('$.now during "T9999"'));
    helper.expectACError(() => ac.require('$.now during "D30 M2"'), 'never matches');
  });
});
