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

  describe('during — temporal schedules (dtrexp)', () => {
    const BH = 'T0900:1800 E1:5'; // Mon–Fri, 09:00–18:00
    const monMorning = { now: '2026-07-20T10:00:00Z', tz: 'UTC' }; // in window
    const satMorning = { now: '2026-07-18T10:00:00Z', tz: 'UTC' }; // out (weekend)

    test('.during() alone gates a grant by schedule (stored canonical)', () => {
      const ac = new AccessControl();
      ac.grant('editor').during(BH).updateAny('post', ['*']);
      const grants = ac.getGrants() as any;
      expect(grants.editor.post.update[0].condition).toEqual(['$.now', 'during', BH]);
      expect(ac.can('editor', monMorning).updateAny('post').granted).toBe(true);
      expect(ac.can('editor', satMorning).updateAny('post').granted).toBe(false);
    });

    test('.where().during() — both must hold (AND)', () => {
      const ac = new AccessControl();
      ac.grant('trader').where('$.order.value <= 100000').during(BH).updateAny('order', ['*']);
      const grants = ac.getGrants() as any;
      expect(grants.trader.order.update[0].condition).toEqual({
        and: [
          ['$.order.value', '<=', 100000],
          ['$.now', 'during', BH]
        ]
      });
      const small = { order: { value: 500 } };
      const large = { order: { value: 500000 } };
      expect(ac.can('trader', { ...monMorning, ...small }).updateAny('order').granted).toBe(true);
      expect(ac.can('trader', { ...monMorning, ...large }).updateAny('order').granted).toBe(false);
      expect(ac.can('trader', { ...satMorning, ...small }).updateAny('order').granted).toBe(false);
    });

    test('.during().where() — the schedule survives a later .where() (order-independent)', () => {
      const ac = new AccessControl();
      ac.grant('trader').during(BH).where('$.order.value <= 100000').updateAny('order', ['*']);
      // the schedule is folded at commit — .where()'s overwrite cannot drop it
      const grants = ac.getGrants() as any;
      expect(grants.trader.order.update[0].condition).toEqual({
        and: [
          ['$.order.value', '<=', 100000],
          ['$.now', 'during', BH]
        ]
      });
      const small = { order: { value: 500 } };
      expect(ac.can('trader', { ...satMorning, ...small }).updateAny('order').granted).toBe(false);
      expect(ac.can('trader', { ...monMorning, ...small }).updateAny('order').granted).toBe(true);
    });

    test('repeated .during() calls AND together', () => {
      const ac = new AccessControl();
      // weekday business hours AND within July 2026
      ac.grant('temp').during(BH).during('20260701:20260731').readAny('report', ['*']);
      const grants = ac.getGrants() as any;
      expect(grants.temp.report.read[0].condition).toEqual({
        and: [
          ['$.now', 'during', BH],
          ['$.now', 'during', '20260701:20260731']
        ]
      });
      expect(ac.can('temp', monMorning).readAny('report').granted).toBe(true);
      // a Monday in-window but outside July 2026
      expect(
        ac.can('temp', { now: '2026-08-03T10:00:00Z', tz: 'UTC' }).readAny('report').granted
      ).toBe(false);
    });

    test('.during() does not leak to later chained actions', () => {
      const ac = new AccessControl();
      ac.grant('editor').during(BH).updateAny('post', ['*']).readAny('post', ['*']);
      const grants = ac.getGrants() as any;
      expect(grants.editor.post.update[0].condition).toEqual(['$.now', 'during', BH]);
      expect(grants.editor.post.read[0].condition).toBeUndefined();
      // read works out-of-window; update does not
      expect(ac.can('editor', satMorning).readAny('post').granted).toBe(true);
      expect(ac.can('editor', satMorning).updateAny('post').granted).toBe(false);
    });

    test('a schedule-only denial carries reason "out_of_schedule" (granted, but not now)', () => {
      const ac = new AccessControl();
      ac.grant('editor').during(BH).updateAny('post', ['*']);
      let eventReason = '';
      ac.on('access', (e: any) => {
        eventReason = e.reason ?? '';
      });
      const denied = ac.can('editor', satMorning).updateAny('post');
      expect(denied.granted).toBe(false);
      expect(denied.reason).toBe('out_of_schedule'); // public Permission getter
      expect(eventReason).toBe('out_of_schedule'); // audit event carries it too
      // granted → reason is undefined
      expect(ac.can('editor', monMorning).updateAny('post').reason).toBeUndefined();
    });

    test('out_of_schedule only when time is the ONLY blocker', () => {
      const ac = new AccessControl();
      ac.grant('trader').where('$.order.value <= 100000').during(BH).updateAny('order', ['*']);
      const small = { order: { value: 500 } };
      const large = { order: { value: 500000 } };
      // schedule blocks, value passes → would be granted at a covered instant
      expect(ac.can('trader', { ...satMorning, ...small }).updateAny('order').reason).toBe(
        'out_of_schedule'
      );
      // value blocks (in-window) → generic condition failure
      expect(ac.can('trader', { ...monMorning, ...large }).updateAny('order').reason).toBe(
        'condition_failed'
      );
      // BOTH block → "come back later" would be a lie
      expect(ac.can('trader', { ...satMorning, ...large }).updateAny('order').reason).toBe(
        'condition_failed'
      );
    });

    test('any rule blocked only by time ⇒ out_of_schedule (union semantics)', () => {
      const ac = new AccessControl();
      // two independent rules for the same action: one value-gated, one scheduled
      ac.grant('editor').where('$.vip == true').updateAny('post', ['*']);
      ac.grant('editor').during(BH).updateAny('post', ['*']);
      // out of window + not vip: the scheduled rule alone would grant in-window
      expect(ac.can('editor', { ...satMorning, vip: false }).updateAny('post').reason).toBe(
        'out_of_schedule'
      );
    });

    test('a failing `not during` reads as condition_failed, not out_of_schedule', () => {
      const ac = new AccessControl();
      // "only OUTSIDE business hours" — failing it means you're inside the
      // schedule; "out of schedule" would be backwards.
      ac.grant('maintenance').where('$.now not during "T0900:1800 E1:5"').deleteAny('cache', ['*']);
      expect(ac.can('maintenance', monMorning).deleteAny('cache').reason).toBe('condition_failed');
    });

    test('schedule under `not` keeps its assumed polarity (negation is honored)', () => {
      // and(during(BH), not(during(E1:5))): on Saturday BOTH durings are false,
      // so the original condition fails on BH but `not(E1:5)` holds. Assuming
      // schedules satisfied flips the `not` arm to false — the rule would still
      // not grant, so this must NOT read as out_of_schedule. (A transform that
      // ignored the negated schedule would wrongly report out_of_schedule.)
      const ac = new AccessControl();
      ac.grant('editor')
        .where({ and: [`$.now during "${BH}"`, { not: '$.now during "E1:5"' }] })
        .updateAny('post', ['*']);
      expect(ac.can('editor', satMorning).updateAny('post').reason).toBe('condition_failed');
    });

    test('a value predicate under `not` survives the schedule assumption', () => {
      // and(during, not(vip)): schedule fails, not(vip=false) passes — time is
      // the only blocker, through a `not` combinator.
      const ac = new AccessControl();
      ac.grant('editor')
        .where({ and: [`$.now during "${BH}"`, { not: '$.vip == true' }] })
        .updateAny('post', ['*']);
      expect(ac.can('editor', { ...satMorning, vip: false }).updateAny('post').reason).toBe(
        'out_of_schedule'
      );
    });

    test('async path resolves the same reasons', async () => {
      const ac = new AccessControl();
      ac.grant('editor').during(BH).updateAny('post', ['*']);
      const denied = ac.can('editor', satMorning).updateAny('post');
      expect(await denied.grantedAsync).toBe(false);
      expect(denied.reason).toBe('out_of_schedule');
    });

    test('or-combined schedule: time-only blocker still reads out_of_schedule', () => {
      const ac = new AccessControl();
      ac.grant('editor')
        .where({ or: ['$.vip == true', `$.now during "${BH}"`] })
        .updateAny('post', ['*']);
      // neither arm holds, but assuming the schedule satisfied the `or` passes
      expect(ac.can('editor', { ...satMorning, vip: false }).updateAny('post').reason).toBe(
        'out_of_schedule'
      );
    });

    test('sync fail-safe: a schedule probe that reaches a custom fn reads condition_failed', () => {
      const ac = new AccessControl();
      // the main sync eval short-circuits on the failed schedule (fn never
      // reached, no asyncRequired) — the schedule-only probe WOULD reach the
      // fn, throws internally, and fails safe to the generic reason.
      ac.grant('editor')
        .where({ and: [`$.now during "${BH}"`, { fn: 'vip' }] })
        .updateAny('post', ['*']);
      const denied = ac.can('editor', satMorning).updateAny('post');
      expect(denied.granted).toBe(false);
      expect(denied.reason).toBe('condition_failed');
    });

    test('async rule path: schedule reason + fail-safe probe (custom fns present)', async () => {
      // rule1 starts with a fn so the check must resolve async
      const ac = new AccessControl();
      ac.defineCondition('never', () => false);
      ac.grant('editor').where({ fn: 'never' }).updateAny('post', ['*']);
      ac.grant('editor').during(BH).updateAny('post', ['*']);
      const denied = ac.can('editor', satMorning).updateAny('post');
      // the scheduled rule alone would grant in-window → out_of_schedule
      expect(await denied.grantedAsync).toBe(false);
      expect(denied.reason).toBe('out_of_schedule');

      // and the async probe fails safe when it reaches a throwing fn the main
      // evaluation short-circuited past
      const ac2 = new AccessControl();
      ac2.defineCondition('never', () => false);
      ac2.defineCondition('boom', () => {
        throw new Error('boom');
      });
      ac2.grant('editor').where({ fn: 'never' }).updateAny('post', ['*']);
      ac2
        .grant('editor')
        .where({ and: [`$.now during "${BH}"`, { fn: 'boom' }] })
        .updateAny('post', ['*']);
      const denied2 = ac2.can('editor', satMorning).updateAny('post');
      expect(await denied2.grantedAsync).toBe(false);
      expect(denied2.reason).toBe('condition_failed');
    });

    test('custom engine.pathPrefix applies to .during() leaves too', () => {
      const ac = new AccessControl({}, { engine: { pathPrefix: '@' } });
      ac.grant('editor').during(BH).updateAny('post', ['*']);
      const grants = ac.getGrants() as any;
      expect(grants.editor.post.update[0].condition).toEqual(['@.now', 'during', BH]);
      expect(ac.can('editor', monMorning).updateAny('post').granted).toBe(true);
      expect(ac.can('editor', satMorning).updateAny('post').granted).toBe(false);
    });

    test('an invalid .during() expression throws when the chain commits', () => {
      const ac = new AccessControl();
      expect(() => ac.grant('editor').during('T9999').updateAny('post', ['*'])).toThrow(/during/);
      expect(() => ac.grant('editor').during('D30 M2').updateAny('post', ['*'])).toThrow(
        /never matches/
      );
    });

    test('async path: grantedAsync resolves the same schedule verdicts', async () => {
      const ac = new AccessControl();
      ac.grant('editor').during(BH).updateAny('post', ['*']);
      expect(await ac.can('editor', monMorning).updateAny('post').grantedAsync).toBe(true);
      expect(await ac.can('editor', satMorning).updateAny('post').grantedAsync).toBe(false);
    });
  });
});
