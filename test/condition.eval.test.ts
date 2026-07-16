/**
 *  Test Suite: condition evaluator (canonical JSON → boolean, §5.3/§5.4).
 */

import {
  assumeSchedules,
  compileCondition,
  evaluateCondition,
  evaluateConditionAsync,
  getDTRExp
} from '../src/utils/index.js';
import { helper } from './helper.js';

// Convenience: compile sugar then evaluate against a context.
const check = (expr: any, ctx: any = {}, prefix = '$') =>
  evaluateCondition(compileCondition(expr, prefix), ctx, prefix);

describe('Test Suite: condition evaluator', () => {
  test('comparison operators', () => {
    expect(check('$.order.value > 100000', { order: { value: 150000 } })).toBe(true);
    expect(check('$.order.value > 100000', { order: { value: 50000 } })).toBe(false);
    expect(check('$.a >= 5', { a: 5 })).toBe(true);
    expect(check('$.a <= 5', { a: 6 })).toBe(false);
    expect(check('$.a < 5', { a: 4 })).toBe(true);
    expect(check('$.a < 5', { a: 5 })).toBe(false);
    expect(check('$.role == admin', { role: 'admin' })).toBe(true);
    expect(check('$.role != admin', { role: 'user' })).toBe(true);
    // strict equality: '100' (forced string) !== 100 (number)
    expect(check('$.code == "100"', { code: 100 })).toBe(false);
    expect(check('$.code == 100', { code: 100 })).toBe(true);
    // boolean / null literals match real boolean / null context values
    expect(check('$.user.active == true', { user: { active: true } })).toBe(true);
    expect(check('$.user.active == false', { user: { active: true } })).toBe(false);
    expect(check('$.deletedAt == null', { deletedAt: null })).toBe(true);
    expect(check('$.s == "true"', { s: 'true' })).toBe(true); // quoted stays string
  });

  test('type inference: strict equality never coerces number ↔ string', () => {
    // RHS `100` is a number no matter the field name → only matches a number
    expect(check('$.num == 100', { num: 100 })).toBe(true);
    expect(check('$.num == 100', { num: '100' })).toBe(false); // string ctx, number rhs
    expect(check('$.str == 100', { str: '100' })).toBe(false); // the gotcha: no coercion
    // quoting the literal makes it a string → matches the string context
    expect(check('$.str == "100"', { str: '100' })).toBe(true);
    expect(check('$.str == "100"', { str: 100 })).toBe(false);
    // plain alphabetic enums need no quotes
    expect(check('$.status != locked', { status: 'active' })).toBe(true);
    expect(check('$.status != locked', { status: 'locked' })).toBe(false);
  });

  test('=== / !== behave identically to == / != (strict)', () => {
    expect(check('$.a === 1', { a: 1 })).toBe(true);
    expect(check('$.a === 1', { a: '1' })).toBe(false); // strict, like ==
    expect(check('$.a !== 1', { a: 2 })).toBe(true);
    expect(check('$.role === admin', { role: 'admin' })).toBe(true);
  });

  test('path vs path operands', () => {
    expect(
      check('$.user.id == $.order.creatorId', { user: { id: 7 }, order: { creatorId: 7 } })
    ).toBe(true);
    expect(
      check('$.user.id != $.order.creatorId', { user: { id: 7 }, order: { creatorId: 9 } })
    ).toBe(true);
  });

  test('membership + string operators', () => {
    expect(check('$.role in [admin, manager]', { role: 'manager' })).toBe(true);
    expect(check('$.role in [admin, manager]', { role: 'user' })).toBe(false);
    expect(check('$.tags contains urgent', { tags: ['urgent', 'new'] })).toBe(true);
    expect(check('$.name contains foo', { name: 'foobar' })).toBe(true);
    expect(check('$.name matches ^a.*z$', { name: 'abcz' })).toBe(true);
    expect(check('$.file endsWith .pdf', { file: 'report.pdf' })).toBe(true);
    expect(check('$.file startsWith report', { file: 'report.pdf' })).toBe(true);
  });

  test('combinators and `not`', () => {
    const ctx = { order: { value: 150000 }, user: { id: 1 } };
    expect(check({ and: ['$.order.value > 100000', '$.user.id == 1'] }, ctx)).toBe(true);
    expect(check({ and: ['$.order.value > 100000', '$.user.id == 2'] }, ctx)).toBe(false);
    expect(check({ or: ['$.order.value > 999999', '$.user.id == 1'] }, ctx)).toBe(true);
    expect(check('$.user.id not == 2', ctx)).toBe(true);
    expect(check('$.user.id not == 1', ctx)).toBe(false);
  });

  test('between — numbers and overnight-wrapping time', () => {
    expect(check('$.x between [1, 10]', { x: 5 })).toBe(true);
    expect(check('$.x between [1, 10]', { x: 11 })).toBe(false);
    // normal daytime window
    expect(check('$.t between [09:00, 17:00]', { t: '12:30' })).toBe(true);
    expect(check('$.t between [09:00, 17:00]', { t: '18:00' })).toBe(false);
    // overnight wrap 21:00 → 03:00
    expect(check('$.t between [21:00, 03:00]', { t: '23:30' })).toBe(true);
    expect(check('$.t between [21:00, 03:00]', { t: '02:00' })).toBe(true);
    expect(check('$.t between [21:00, 03:00]', { t: '12:00' })).toBe(false);
  });

  test('before / after (dates)', () => {
    expect(check('$.d before 2026-06-01', { d: '2026-01-01' })).toBe(true);
    expect(check('$.d after 2026-06-01', { d: '2026-12-01' })).toBe(true);
    expect(check('$.d after 2026-06-01', { d: '2026-01-01' })).toBe(false);
    // non-temporal strings fall back to lexical comparison
    expect(check('$.a before zzz', { a: 'aaa' })).toBe(true);
  });

  test('IP membership — in [CIDR/IP] and cidr alias', () => {
    expect(check('$.ip in [10.0.0.0/8, 192.168.1.1]', { ip: '10.4.5.6' })).toBe(true);
    expect(check('$.ip in [10.0.0.0/8, 192.168.1.1]', { ip: '192.168.1.1' })).toBe(true);
    expect(check('$.ip in [10.0.0.0/8, 192.168.1.1]', { ip: '172.16.0.1' })).toBe(false);
    expect(check('$.ip cidr 10.0.0.0/8', { ip: '10.255.255.255' })).toBe(true);
    expect(check('$.ip cidr 10.0.0.0/8', { ip: '11.0.0.1' })).toBe(false);
    expect(check('$.ip cidr 10.1.2.3/32', { ip: '10.1.2.3' })).toBe(true);
  });

  test('$.now.* derived fields (deterministic via fixed now + tz)', () => {
    // 2026-06-19 is a Friday; 14:30 UTC
    const now = new Date('2026-06-19T14:30:00Z');
    const ctx = { now, tz: 'UTC' };
    expect(check('$.now.weekday == fri', ctx)).toBe(true);
    expect(check('$.now.month == jun', ctx)).toBe(true);
    expect(check('$.now.year == 2026', ctx)).toBe(true);
    expect(check('$.now.day == 19', ctx)).toBe(true);
    expect(check('$.now.date == 2026-06-19', ctx)).toBe(true);
    expect(check('$.now.hour == 14', ctx)).toBe(true);
    expect(check('$.now.time between [09:00, 17:00]', ctx)).toBe(true);
    // timezone shifts the wall clock: UTC 14:30 → Istanbul 17:30 (out of window)
    expect(check('$.now.time between [09:00, 17:00]', { now, tz: 'Europe/Istanbul' })).toBe(false);
  });

  test('worked example — Friday business-hours grant', () => {
    const cond = {
      and: ['$.now.weekday == fri', '$.now.time between [09:00,17:00]']
    };
    const friNoon = { now: new Date('2026-06-19T12:00:00Z'), tz: 'UTC' };
    const satNoon = { now: new Date('2026-06-20T12:00:00Z'), tz: 'UTC' };
    expect(evaluateCondition(compileCondition(cond), friNoon)).toBe(true);
    expect(evaluateCondition(compileCondition(cond), satNoon)).toBe(false);
  });

  test('throws on uncompiled / invalid / custom-fn nodes', () => {
    helper.expectACError(() => evaluateCondition('$.a == 1' as any)); // not compiled
    helper.expectACError(() => evaluateCondition({ fn: 'x' } as any)); // custom fn (P8)
    helper.expectACError(() => evaluateCondition(42 as any));
    // invalid regex surfaces at evaluation time as an AccessControlError
    helper.expectACError(() => check('$.name matches (', { name: 'x' }));
    // `not` with no right-hand operand
    helper.expectACError(() => compileCondition('$.a not >'));
  });

  describe('during — dtrexp schedules (§5.7)', () => {
    // business hours: Mon–Fri, 09:00–18:00 (half-open per dtrexp `T`)
    const BH = '$.now during "T0900:1800 E1:5"';
    // 2026-07-20 is a Monday; 2026-07-18 a Saturday.

    test('covers/misses the window (deterministic via fixed now + tz)', () => {
      expect(check(BH, { now: '2026-07-20T10:00:00Z', tz: 'UTC' })).toBe(true);
      expect(check(BH, { now: '2026-07-18T10:00:00Z', tz: 'UTC' })).toBe(false); // Saturday
      // half-open time window: start inclusive, end exclusive
      expect(check(BH, { now: '2026-07-20T09:00:00Z', tz: 'UTC' })).toBe(true);
      expect(check(BH, { now: '2026-07-20T18:00:00Z', tz: 'UTC' })).toBe(false);
      // Date instance for `now` behaves identically to the ISO string
      expect(check(BH, { now: new Date('2026-07-20T10:00:00Z'), tz: 'UTC' })).toBe(true);
    });

    test('context.tz shifts the evaluation zone (same instant, different verdicts)', () => {
      const now = '2026-07-20T16:30:00Z'; // 16:30 UTC = 19:30 in Istanbul (UTC+3)
      expect(check(BH, { now, tz: 'UTC' })).toBe(true);
      expect(check(BH, { now, tz: 'Europe/Istanbul' })).toBe(false);
    });

    test('tz omitted ⇒ system zone, consistent with $.now.* derivation', () => {
      // no `tz` in context: `during` must evaluate in the *system* zone — the
      // same default deriveNow uses. The expectation is computed from Intl
      // itself, so the test is exact in any zone (CI pins a non-UTC TZ so the
      // system-zone default stays distinguishable from dtrexp's UTC default).
      // 16:30 UTC Monday: in-window under UTC, out-of-window in zones ≥ UTC+2
      // — so a mutant hardcoding UTC gives the wrong answer on any such system
      // zone (dev machines + CI both pin a non-UTC TZ).
      const now = new Date('2026-07-20T16:30:00Z');
      const parts = new Intl.DateTimeFormat('en-US', {
        weekday: 'short',
        hour: '2-digit',
        hour12: false
      }).formatToParts(now);
      const get = (t: string) => parts.find((p) => p.type === t)?.value ?? '';
      const isWeekday = !['Sat', 'Sun'].includes(get('weekday'));
      const hour = Number(get('hour')) % 24; // some engines render midnight as 24
      const expected = isWeekday && hour >= 9 && hour < 18;
      expect(check(BH, { now })).toBe(expected);
      // …and it agrees with the Intl-derived $.now fields for the same context.
      expect(check('$.now.hour between [9, 17]', { now })).toBe(expected);
      // a non-string tz is ignored (treated as absent → system zone), never
      // passed through to dtrexp (which would throw a RangeError on it).
      expect(check(BH, { now, tz: 123 })).toBe(expected);
    });

    test('any date-like LHS: Date, epoch ms, ISO string, { epochMilliseconds }', () => {
      const cond = '$.meeting.start during "T0900:1800 E1:5"';
      const inWindow = Date.parse('2026-07-20T10:00:00Z');
      const ctxOf = (start: unknown) => ({ meeting: { start }, tz: 'UTC' });
      expect(check(cond, ctxOf(new Date(inWindow)))).toBe(true);
      expect(check(cond, ctxOf(inWindow))).toBe(true);
      expect(check(cond, ctxOf('2026-07-20T10:00:00Z'))).toBe(true);
      expect(check(cond, ctxOf({ epochMilliseconds: inWindow }))).toBe(true);
      // out-of-window instant misses through every shape
      expect(check(cond, ctxOf('2026-07-18T10:00:00Z'))).toBe(false);
    });

    test('fail-closed: a non-date-like LHS evaluates false, never throws', () => {
      const cond = '$.x during "T0900:1800 E1:5"';
      expect(check(cond, { x: 'admin', tz: 'UTC' })).toBe(false);
      expect(check(cond, { x: null, tz: 'UTC' })).toBe(false);
      expect(check(cond, { tz: 'UTC' })).toBe(false); // missing path → undefined
      expect(check(cond, { x: Number.NaN, tz: 'UTC' })).toBe(false);
      expect(check(cond, { x: Number.POSITIVE_INFINITY, tz: 'UTC' })).toBe(false);
      expect(check(cond, { x: new Date('nope'), tz: 'UTC' })).toBe(false); // Invalid Date
      expect(check(cond, { x: {}, tz: 'UTC' })).toBe(false);
      expect(check(cond, { x: { epochMilliseconds: '5' }, tz: 'UTC' })).toBe(false);
      expect(check(cond, { x: { epochMilliseconds: Number.NaN }, tz: 'UTC' })).toBe(false);
    });

    test('direct eval of a canonical leaf: non-string rhs is false; invalid expr throws coded', () => {
      const ctx = { now: '2026-07-20T10:00:00Z', tz: 'UTC' };
      // bypassing the compiler: a non-string rhs fails closed
      expect(evaluateCondition(['$.now', 'during', 42] as any, ctx)).toBe(false);
      // …but a malformed expression string throws (the `matches` precedent)
      helper.expectACError(() => evaluateCondition(['$.now', 'during', 'T9999'] as any, ctx));
      try {
        evaluateCondition(['$.now', 'during', 'T9999'] as any, ctx);
      } catch (err: any) {
        expect(err.code).toBe('INVALID_DTREXP');
      }
    });

    test('async parity: the same leaves through evaluateConditionAsync', async () => {
      const leaf = compileCondition(BH);
      expect(await evaluateConditionAsync(leaf, { now: '2026-07-20T10:00:00Z', tz: 'UTC' })).toBe(
        true
      );
      expect(await evaluateConditionAsync(leaf, { now: '2026-07-18T10:00:00Z', tz: 'UTC' })).toBe(
        false
      );
      expect(
        await evaluateConditionAsync(['$.x', 'during', 'E1:5'] as any, { x: 'nope', tz: 'UTC' })
      ).toBe(false);
    });

    test('assumeSchedules: non-node values pass through unchanged', () => {
      // the transform maps structure only — it neither validates nor compiles
      expect(assumeSchedules('$.a == 1' as any)).toBe('$.a == 1');
      expect(assumeSchedules({ fn: 'vip' } as any)).toEqual({ fn: 'vip' });
      expect(assumeSchedules(['$.a', '==', 1])).toEqual(['$.a', '==', 1]);
      expect(assumeSchedules(['$.now', 'during', 'E1:5'])).toEqual([1, '==', 1]);
    });

    test('parse cache: identity on hit; FIFO eviction past the bound', () => {
      // distinct valid one-minute windows: T0000:0001, T0001:0002, …
      const expr = (i: number) => {
        const pad = (m: number) =>
          `${String(Math.floor(m / 60)).padStart(2, '0')}${String(m % 60).padStart(2, '0')}`;
        return `T${pad(i)}:${pad(i + 1)}`;
      };
      const first = getDTRExp(expr(0));
      expect(getDTRExp(expr(0))).toBe(first); // cache hit → same instance
      // flood with 500 more distinct expressions (MAX_DTREXP_CACHE = 500):
      // whatever else the suite cached, `first` is evicted by insertion order.
      for (let i = 1; i <= 500; i++) getDTRExp(expr(i));
      const last = getDTRExp(expr(500));
      expect(getDTRExp(expr(500))).toBe(last); // recent entry still cached
      expect(getDTRExp(expr(0))).not.toBe(first); // evicted → re-parsed instance
    });
  });

  describe('async evaluator (evaluateConditionAsync, §5.5)', () => {
    const reg = { vip: (ctx: any) => ctx.vip === true, no: () => false };

    test('declarative leaves/combinators match the sync path', async () => {
      expect(await evaluateConditionAsync(compileCondition('$.a == 1'), { a: 1 })).toBe(true);
      // `not` combinator
      expect(await evaluateConditionAsync({ not: compileCondition('$.a == 1') }, { a: 2 })).toBe(
        true
      );
      // and / or with a custom fn mixed in
      expect(
        await evaluateConditionAsync(
          { and: [compileCondition('$.a == 1'), { fn: 'vip' }] },
          { a: 1, vip: true },
          '$',
          reg
        )
      ).toBe(true);
      expect(
        await evaluateConditionAsync({ or: [{ fn: 'no' }, { fn: 'vip' }] }, { vip: true }, '$', reg)
      ).toBe(true);
    });

    test('throws on uncompiled / invalid nodes and unknown fn', async () => {
      await expect(evaluateConditionAsync('$.a == 1' as any)).rejects.toThrow(/compiled/);
      await expect(evaluateConditionAsync(42 as any)).rejects.toThrow(/Invalid condition node/);
      await expect(evaluateConditionAsync({ fn: 'missing' } as any)).rejects.toThrow(
        /Unknown condition/
      );
    });
  });
});
