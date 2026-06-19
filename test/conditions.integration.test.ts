/**
 *  Test Suite: conditions end-to-end (.where / .with / context / resolution).
 *  Verifies P3 wiring: authored conditions gate checks via the public API and
 *  fold into the §5.6 resolution (deny-overrides, inheritance, metadata).
 */

import { AccessControl } from '../src/index.js';

describe('Test Suite: conditions (integration)', () => {
  test('.where() gates a grant; .can(role, context) supplies data', () => {
    const ac = new AccessControl();
    ac.grant('manager').where('$.order.value > 100000').updateAny('order', ['*']);

    expect(ac.can('manager', { order: { value: 150000 } }).updateAny('order').granted).toBe(true);
    expect(ac.can('manager', { order: { value: 50000 } }).updateAny('order').granted).toBe(false);
    // no context ⇒ path is undefined ⇒ condition fails ⇒ not granted
    expect(ac.can('manager').updateAny('order').granted).toBe(false);
  });

  test('.with() is the fluent equivalent of the can() 2nd argument', () => {
    const ac = new AccessControl();
    ac.grant('manager').where('$.order.value > 100000').updateAny('order', ['*']);
    expect(
      ac
        .can('manager')
        .with({ order: { value: 150000 } })
        .updateAny('order').granted
    ).toBe(true);
  });

  test('check() one-shot reads context from the query object', () => {
    const ac = new AccessControl();
    ac.grant('manager').where('$.order.value > 100000').updateAny('order', ['*']);
    expect(
      ac.check({
        role: 'manager',
        resource: 'order',
        action: 'update:any',
        context: { order: { value: 150000 } }
      }).granted
    ).toBe(true);
    expect(
      ac.check({
        role: 'manager',
        resource: 'order',
        action: 'update:any',
        context: { order: { value: 5 } }
      }).granted
    ).toBe(false);
  });

  test('conditions are stored canonical (JSONB-ready) in the grants model', () => {
    const ac = new AccessControl();
    ac.grant('manager').where('$.order.value > 100000').updateAny('order', ['*']);
    const grants = ac.getGrants() as any;
    expect(grants.manager.order.update[0].condition).toEqual(['$.order.value', '>', 100000]);
  });

  test('ambient context (constructor) is overridden per-check (per-check wins)', () => {
    const ac = new AccessControl({}, { context: { region: 'eu' } });
    ac.grant('reader').where('$.region == eu').readAny('doc', ['*']);
    expect(ac.can('reader').readAny('doc').granted).toBe(true); // ambient eu
    expect(ac.can('reader', { region: 'us' }).readAny('doc').granted).toBe(false); // override
  });

  test('query metadata wins over caller context (no spoofing what you check)', () => {
    const ac = new AccessControl();
    // grant only applies to the "read" action
    ac.grant('user').where('$.action == read').updateAny('doc', ['*']);
    // caller tries to spoof $.action via context — metadata ($.action='update') wins
    expect(ac.can('user', { action: 'read' }).updateAny('doc').granted).toBe(false);

    ac.grant('user').where('$.action == read').readAny('doc', ['*']);
    expect(ac.can('user').readAny('doc').granted).toBe(true);
  });

  test('a failed condition contributes nothing and shadows nothing (§5.6)', () => {
    const ac = new AccessControl();
    // unconditional grant + conditional deny
    ac.grant('editor').readAny('post', ['*', '!secret']);
    ac.deny('editor').where('$.post.status == locked').readAny('post');

    // deny applies → subtract all → not granted
    expect(ac.can('editor', { post: { status: 'locked' } }).readAny('post').granted).toBe(false);
    // deny condition fails → deny drops out → base grant stands
    const perm = ac.can('editor', { post: { status: 'open' } }).readAny('post');
    expect(perm.granted).toBe(true);
    expect(perm.attributes).toEqual(['*', '!secret']);
  });

  test('conditions evaluate across the inheritance chain', () => {
    const ac = new AccessControl();
    ac.grant('base').where('$.tenant == acme').readAny('report', ['*']);
    ac.grant('admin').extend('base');
    expect(ac.can('admin', { tenant: 'acme' }).readAny('report').granted).toBe(true);
    expect(ac.can('admin', { tenant: 'other' }).readAny('report').granted).toBe(false);
  });

  test('$.now-based grant (deterministic via injected now)', () => {
    const ac = new AccessControl();
    ac.grant('manager').where('$.now.weekday != fri').deleteAny('record', ['*']);
    const thu = { now: new Date('2026-06-18T10:00:00Z'), tz: 'UTC' };
    const fri = { now: new Date('2026-06-19T10:00:00Z'), tz: 'UTC' };
    expect(ac.can('manager', thu).deleteAny('record').granted).toBe(true);
    expect(ac.can('manager', fri).deleteAny('record').granted).toBe(false);
  });

  test('custom engine.pathPrefix applies to authoring and checking', () => {
    const ac = new AccessControl({}, { engine: { pathPrefix: '@' } });
    ac.grant('svc').where('@.score >= 10').readAny('thing', ['*']);
    const grants = ac.getGrants() as any;
    expect(grants.svc.thing.read[0].condition).toEqual(['@.score', '>=', 10]);
    expect(ac.can('svc', { score: 12 }).readAny('thing').granted).toBe(true);
    expect(ac.can('svc', { score: 3 }).readAny('thing').granted).toBe(false);
  });

  test('.where() condition does not leak to later chained actions', () => {
    const ac = new AccessControl();
    ac.grant('manager')
      .where('$.order.value > 100000')
      .updateAny('order', ['*'])
      .readAny('report', ['*']);
    const grants = ac.getGrants() as any;
    expect(grants.manager.order.update[0].condition).toEqual(['$.order.value', '>', 100000]);
    expect(grants.manager.report.read[0].condition).toBeUndefined();
    // report is readable with no context
    expect(ac.can('manager').readAny('report').granted).toBe(true);
  });
});
