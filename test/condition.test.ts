/**
 *  Test Suite: condition compiler (string sugar → canonical JSON, §5.2/§5.3).
 */

import { compileCondition } from '../src/utils/index.js';
import { helper } from './helper.js';

describe('Test Suite: condition compiler', () => {
  test('comparison leaves — typed operands', () => {
    expect(compileCondition('$.order.value > 100000')).toEqual(['$.order.value', '>', 100000]);
    expect(compileCondition('$.a == 1')).toEqual(['$.a', '==', 1]);
    expect(compileCondition('$.a >= -2.5')).toEqual(['$.a', '>=', -2.5]);
    // path on both sides
    expect(compileCondition('$.user.id != $.order.creatorId')).toEqual([
      '$.user.id',
      '!=',
      '$.order.creatorId'
    ]);
  });

  test('barewords are strings; quotes optional and force string type', () => {
    expect(compileCondition('$.role == admin')).toEqual(['$.role', '==', 'admin']);
    expect(compileCondition('$.name endsWith .pdf')).toEqual(['$.name', 'endsWith', '.pdf']);
    expect(compileCondition('$.name endsWith ".pdf"')).toEqual(['$.name', 'endsWith', '.pdf']);
    // quotes force string even when numeric-looking
    expect(compileCondition('$.code == "100"')).toEqual(['$.code', '==', '100']);
    expect(compileCondition('$.code == 100')).toEqual(['$.code', '==', 100]);
  });

  test('boolean and null barewords become literals; quotes force string', () => {
    expect(compileCondition('$.user.active == true')).toEqual(['$.user.active', '==', true]);
    expect(compileCondition('$.user.active == false')).toEqual(['$.user.active', '==', false]);
    expect(compileCondition('$.deletedAt == null')).toEqual(['$.deletedAt', '==', null]);
    // quotes keep the string form
    expect(compileCondition('$.s == "true"')).toEqual(['$.s', '==', 'true']);
    expect(compileCondition('$.s == "null"')).toEqual(['$.s', '==', 'null']);
  });

  test('`not` modifier compiles to a { not: leaf } wrapper', () => {
    expect(compileCondition('$.file.name not startsWith report_')).toEqual({
      not: ['$.file.name', 'startsWith', 'report_']
    });
    expect(compileCondition('$.now.time not between [09:00,17:00]')).toEqual({
      not: ['$.now.time', 'between', ['09:00', '17:00']]
    });
    // `!=` is its own operator, not the `not` modifier
    expect(compileCondition('$.a != 1')).toEqual(['$.a', '!=', 1]);
  });

  test('membership + string operators', () => {
    expect(compileCondition('$.role in [admin, manager]')).toEqual([
      '$.role',
      'in',
      ['admin', 'manager']
    ]);
    expect(compileCondition('$.tags contains urgent')).toEqual(['$.tags', 'contains', 'urgent']);
    expect(compileCondition('$.name matches ^a.*z$')).toEqual(['$.name', 'matches', '^a.*z$']);
  });

  test('between — inclusive; numeric/date order validated, time wraps', () => {
    expect(compileCondition('$.x between [1, 10]')).toEqual(['$.x', 'between', [1, 10]]);
    helper.expectACError(() => compileCondition('$.x between [10, 1]'));
    helper.expectACError(() => compileCondition('$.d between [2026-12-01, 2026-01-01]'));
    // time-of-day overnight wrap is allowed (start > end)
    expect(compileCondition('$.now.time between [21:00, 03:00]')).toEqual([
      '$.now.time',
      'between',
      ['21:00', '03:00']
    ]);
    helper.expectACError(() => compileCondition('$.x between [1]'));
  });

  test('network — IP/CIDR validated at compile time; cidr alias', () => {
    expect(compileCondition('$.ip in [10.0.0.0/8, 192.168.1.1]')).toEqual([
      '$.ip',
      'in',
      ['10.0.0.0/8', '192.168.1.1']
    ]);
    expect(compileCondition('$.ip cidr 10.0.0.0/8')).toEqual(['$.ip', 'cidr', '10.0.0.0/8']);
    helper.expectACError(() => compileCondition('$.ip cidr 10.0.0.0/99')); // bad prefix
    helper.expectACError(() => compileCondition('$.ip in [10.0.0.0/8, 999.1.1.1]')); // bad octet
  });

  test('combinators compile recursively', () => {
    expect(
      compileCondition({ and: ['$.order.value > 100000', '$.user.id != $.order.creatorId'] })
    ).toEqual({
      and: [
        ['$.order.value', '>', 100000],
        ['$.user.id', '!=', '$.order.creatorId']
      ]
    });
    expect(compileCondition({ or: ['$.a == 1'] })).toEqual({ or: [['$.a', '==', 1]] });
    expect(compileCondition({ not: '$.a == 1' })).toEqual({ not: ['$.a', '==', 1] });
  });

  test('idempotent — canonical input validates and passes through', () => {
    const canonical = ['$.a', '>', 1];
    expect(compileCondition(canonical as any)).toEqual(canonical);
    expect(compileCondition({ and: [['$.a', '>', 1]] } as any)).toEqual({
      and: [['$.a', '>', 1]]
    });
  });

  test('custom-fn reference passes through unchanged', () => {
    const fn = { fn: 'isBusinessHours', args: { tz: 'Europe/Istanbul' } };
    expect(compileCondition(fn as any)).toEqual(fn);
  });

  test('configurable pathPrefix', () => {
    // with prefix '@', `$.foo` is a literal string and `@.foo` is the path
    expect(compileCondition('@.order.value > 100', '@')).toEqual(['@.order.value', '>', 100]);
    expect(compileCondition('$.foo == bar', '@')).toEqual(['$.foo', '==', 'bar']);
  });

  test('throws on malformed input', () => {
    helper.expectACError(() => compileCondition('$.a'));
    helper.expectACError(() => compileCondition('$.a >'));
    helper.expectACError(() => compileCondition('$.a foo 1')); // unknown op
    helper.expectACError(() => compileCondition("$.a == 'unterminated"));
    helper.expectACError(() => compileCondition('$.a in [1, 2')); // unterminated bracket
    helper.expectACError(() => compileCondition(['$.a', 'foo', 1] as any)); // bad leaf op
    helper.expectACError(() => compileCondition(['$.a', '>'] as any)); // bad leaf arity
    helper.expectACError(() => compileCondition({ and: '$.a == 1' } as any)); // and not array
    helper.expectACError(() => compileCondition(42 as any));
  });

  describe('during — dtrexp schedules (§5.7)', () => {
    // Asserts both the AC error *and* its machine-readable code.
    const expectCode = (fn: () => unknown, code: string, msgPart?: string) => {
      helper.expectACError(fn, msgPart);
      try {
        fn();
      } catch (err: any) {
        expect(err.code).toBe(code);
      }
    };

    test('quoted expression (spaces, `|`, `:`) compiles to the exact triple', () => {
      expect(compileCondition('$.now during "T0900:1800 E1:5"')).toEqual([
        '$.now',
        'during',
        'T0900:1800 E1:5'
      ]);
      // union + single quotes
      expect(compileCondition("$.now during 'T0900:1800 E1:5 | T1000:1400 E6'")).toEqual([
        '$.now',
        'during',
        'T0900:1800 E1:5 | T1000:1400 E6'
      ]);
      // any date-like LHS path, not just $.now
      expect(compileCondition('$.booking.start during "E1:5"')).toEqual([
        '$.booking.start',
        'during',
        'E1:5'
      ]);
    });

    test('unquoted single-token expression compiles (quoting is still the documented form)', () => {
      expect(compileCondition('$.now during T0900:1800')).toEqual([
        '$.now',
        'during',
        'T0900:1800'
      ]);
    });

    test('`not during` compiles to a { not: leaf } wrapper', () => {
      expect(compileCondition('$.now not during "E6:7"')).toEqual({
        not: ['$.now', 'during', 'E6:7']
      });
    });

    test('idempotent — canonical during leaf validates and passes through', () => {
      const leaf = ['$.now', 'during', 'T0900:1800 E1:5'];
      expect(compileCondition(leaf as any)).toEqual(leaf);
    });

    test('throws INVALID_DTREXP on malformed expressions (carries dtrexp position)', () => {
      // hour 99 out of range — dtrexp reports position 1
      expectCode(() => compileCondition('$.now during "T9999"'), 'INVALID_DTREXP', 'position 1');
      expectCode(() => compileCondition(['$.now', 'during', 'T9999'] as any), 'INVALID_DTREXP');
    });

    test('throws DTREXP_NEVER_MATCHES on unsatisfiable expressions', () => {
      // Feb 30th parses but can never match (dtrexp unsatisfiability lint)
      expectCode(
        () => compileCondition('$.now during "D30 M2"'),
        'DTREXP_NEVER_MATCHES',
        'never matches'
      );
      expectCode(() => compileCondition(['$.now', 'during', 'D30 M2'] as any), 'DTREXP_NEVER_MATCHES');
    });

    test('throws INVALID_DTREXP on a non-string, empty, or path rhs (must be static)', () => {
      // assert the guard's own message too — an empty/blank rhs must be caught
      // by the static-string guard, not fall through to the dtrexp parser.
      const GUARD = 'static dtrexp expression string';
      expectCode(() => compileCondition(['$.now', 'during', 42] as any), 'INVALID_DTREXP', GUARD);
      expectCode(
        () => compileCondition(['$.now', 'during', ['E1']] as any),
        'INVALID_DTREXP',
        GUARD
      );
      expectCode(() => compileCondition(['$.now', 'during', ''] as any), 'INVALID_DTREXP', GUARD);
      expectCode(
        () => compileCondition(['$.now', 'during', '  '] as any),
        'INVALID_DTREXP',
        GUARD
      );
      expectCode(
        () => compileCondition(['$.now', 'during', '$.user.schedule'] as any),
        'INVALID_DTREXP',
        'not a context path'
      );
    });

    test('length bound: valid at exactly 1000 chars, rejected above', () => {
      // 'T0900:1800' (10) + ' | E1' × 198 (990) = exactly 1000 chars, valid + satisfiable
      const atBound = `T0900:1800${' | E1'.repeat(198)}`;
      expect(atBound.length).toBe(1000);
      expect(compileCondition(['$.now', 'during', atBound] as any)).toEqual([
        '$.now',
        'during',
        atBound
      ]);
      // 1001 chars → rejected before parsing (content is irrelevant past the bound)
      expectCode(
        () => compileCondition(['$.now', 'during', `${atBound}x`] as any),
        'INVALID_DTREXP',
        'too long'
      );
    });
  });
});
