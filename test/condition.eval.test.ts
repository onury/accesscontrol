/**
 *  Test Suite: condition evaluator (canonical JSON → boolean, §5.3/§5.4).
 */

import { compileCondition, evaluateCondition, evaluateConditionAsync } from '../src/utils/index.js';
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
