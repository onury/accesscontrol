/**
 *  Test Suite: v3 security hardening surface.
 *
 *  Covers the opt-in / fail-closed controls added for production hardening:
 *  tryCan() (fail-closed checks), engine.allowRegex + the ReDoS guard,
 *  engine.charset (ASCII/UNICODE), engine.safeErrors (redacted messages) and
 *  the stable err.code contract.
 */

import { AccessControl, AccessControlError, Charset, ErrorCode } from '../src/index.js';

function grab(fn: () => unknown): any {
  try {
    fn();
  } catch (e) {
    return e;
  }
  throw new Error('expected function to throw');
}

describe('tryCan(): fail-closed checks never throw', () => {
  test('can() throws on strict-unknown role; tryCan() denies', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*']);
    expect(grab(() => ac.can('ghost').readAny('post').granted).code).toBe(ErrorCode.ROLE_NOT_FOUND);
    expect(ac.tryCan('ghost').readAny('post').granted).toBe(false);
    expect(ac.tryCan('ghost').readAny('post').attributes).toEqual([]);
  });

  test('tryCan() grants normally when allowed', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*', '!secret']);
    const p = ac.tryCan('u').readAny('post');
    expect(p.granted).toBe(true);
    expect(p.attributes).toEqual(['*', '!secret']);
  });

  test('tryCan() denies on every malformed input shape', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*']);
    expect(ac.tryCan({} as any).readAny('post').granted).toBe(false); // empty IQueryInfo
    expect(ac.tryCan(undefined as any).readAny('post').granted).toBe(false);
    expect(ac.tryCan(123 as any).readAny('post').granted).toBe(false);
    expect(ac.tryCan('u').readAny('').granted).toBe(false); // invalid resource
  });

  test('tryCan(): a custom/async condition denies on the sync path, resolves on async', async () => {
    const ac = new AccessControl();
    ac.defineCondition('ok', (ctx: any) => ctx.flag === true);
    ac.grant('u').where({ fn: 'ok' }).readAny('post', ['*']);
    // sync: can() throws asyncRequired, tryCan() denies
    expect(grab(() => ac.can('u').readAny('post').granted).code).toBe(ErrorCode.ASYNC_REQUIRED);
    expect(ac.tryCan('u').readAny('post').granted).toBe(false);
    // async: resolves the fn for real
    expect(await ac.tryCan('u', { flag: true }).readAny('post').grantedAsync).toBe(true);
    expect(await ac.tryCan('u', { flag: false }).readAny('post').grantedAsync).toBe(false);
  });

  test('tryCan(): async resolution errors fail closed (unknown condition fn)', async () => {
    const ac = new AccessControl();
    ac.grant('u').where({ fn: 'missing' }).readAny('post', ['*']);
    // can() would reject; tryCan() resolves to a denial
    await expect(ac.can('u').readAny('post').grantedAsync).rejects.toThrow();
    expect(await ac.tryCan('u').readAny('post').grantedAsync).toBe(false);
  });

  test('tryCan(): the error event still fires on a fail-closed denial', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*']);
    let fired = 0;
    ac.on('error', () => fired++);
    expect(ac.tryCan('ghost').readAny('post').granted).toBe(false);
    expect(fired).toBeGreaterThan(0);
  });
});

describe('engine.allowRegex + ReDoS guard', () => {
  test('matches is disabled by default and throws REGEX_DISABLED', () => {
    const ac = new AccessControl();
    ac.grant('u').where('$.name matches ^rep').readAny('post', ['*']);
    const e = grab(() => ac.can('u', { name: 'report' }).readAny('post').granted);
    expect(e.message).toContain('matches');
    // tryCan denies instead of throwing
    expect(ac.tryCan('u', { name: 'report' }).readAny('post').granted).toBe(false);
  });

  test('matches works when allowRegex is enabled', () => {
    const ac = new AccessControl({}, { engine: { allowRegex: true } });
    ac.grant('u').where('$.name matches ^rep').readAny('post', ['*']);
    expect(ac.can('u', { name: 'report' }).readAny('post').granted).toBe(true);
    expect(ac.can('u', { name: 'xxx' }).readAny('post').granted).toBe(false);
  });

  test('catastrophic patterns are rejected even when allowRegex is on', () => {
    const cases = ['(a+)+$', '(.*)*', '(\\d+)*', '(a{1,}){2,}'];
    for (const pat of cases) {
      const ac = new AccessControl({}, { engine: { allowRegex: true } });
      ac.grant('u').where(`$.x matches ${pat}`).readAny('post', ['*']);
      expect(grab(() => ac.can('u', { x: 'aaaa' }).readAny('post').granted).message).toContain(
        'catastrophic'
      );
    }
  });

  test('absurdly long patterns are rejected', () => {
    const ac = new AccessControl({}, { engine: { allowRegex: true } });
    ac.grant('u')
      .where(`$.x matches ${'a'.repeat(1001)}`)
      .readAny('post', ['*']);
    expect(grab(() => ac.can('u', { x: 'a' }).readAny('post').granted).message).toContain(
      'too long'
    );
  });

  test('a malformed (but non-catastrophic) regex still reports cleanly', () => {
    const ac = new AccessControl({}, { engine: { allowRegex: true } });
    ac.grant('u').where('$.x matches (').readAny('post', ['*']);
    expect(grab(() => ac.can('u', { x: 'a' }).readAny('post').granted).message).toContain(
      'Invalid regular expression'
    );
  });

  test('a safe quantified group followed by a catastrophic one is still caught', () => {
    const ac = new AccessControl({}, { engine: { allowRegex: true } });
    // first group `(x)+` is safe (no inner quantifier), the scan continues and
    // flags the second group `(y+)+`
    ac.grant('u').where('$.x matches (x)+(y+)+').readAny('post', ['*']);
    expect(grab(() => ac.can('u', { x: 'xy' }).readAny('post').granted).code).toBe(
      ErrorCode.UNSAFE_REGEX
    );
    // a pattern with only safe quantified groups passes the guard
    const ac2 = new AccessControl({}, { engine: { allowRegex: true } });
    ac2.grant('u').where('$.x matches (x)+(y)+').readAny('post', ['*']);
    expect(ac2.can('u', { x: 'xy' }).readAny('post').granted).toBe(true);
  });
});

describe('engine.charset (ASCII default | UNICODE opt-in)', () => {
  test('ASCII (default) rejects non-ASCII names', () => {
    const ac = new AccessControl();
    expect(grab(() => ac.grant('rölé').readAny('post')).code).toBe(ErrorCode.INVALID_NAME);
  });

  test('UNICODE allows internationalized names', () => {
    const ac = new AccessControl({}, { engine: { charset: Charset.UNICODE } });
    ac.grant('rölé').readAny('пост', ['*']);
    expect(ac.can('rölé').readAny('пост').granted).toBe(true);
    expect(ac.getRoles()).toContain('rölé');
  });

  test('UNICODE still rejects structural chars and gadget names', () => {
    const ac = new AccessControl({}, { engine: { charset: Charset.UNICODE } });
    expect(grab(() => ac.grant('a b').readAny('post')).code).toBe(ErrorCode.INVALID_NAME); // space
    expect(grab(() => ac.grant('__proto__').readAny('post')).code).toBe(ErrorCode.RESERVED_NAME);
    // distinct identity (homograph): Cyrillic vs Latin are different roles
    ac.grant('admin').readAny('post', ['*']); // Latin
    expect(ac.can('admin').readAny('post').granted).toBe(true);
    expect(ac.tryCan('аdmin').readAny('post').granted).toBe(false); // Cyrillic а
  });

  test('charset applies to checks too (a unicode query under ASCII is invalid)', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*']);
    expect(ac.tryCan('rölé').readAny('post').granted).toBe(false);
  });
});

describe('engine.safeErrors + err.code', () => {
  test('messages are redacted by default; values live on structured fields', () => {
    const ac = new AccessControl();
    const e = grab(() => ac.grant('bad name').readAny('post'));
    expect(e.code).toBe(ErrorCode.INVALID_NAME);
    expect(e.message).not.toContain('bad name'); // value not echoed
  });

  test('safeErrors:false produces verbose messages (Got: …)', () => {
    const ac = new AccessControl({}, { engine: { safeErrors: false } });
    const e = grab(() => ac.grant('bad name').readAny('post'));
    expect(e.message).toContain('Got:');
    expect(e.message).toContain('bad name');
    // a non-string dynamic value is JSON-stringified in verbose mode
    const e2 = grab(() => ac.removeRoles([] as any));
    expect(e2.message).toContain('Got: []');
  });

  test('stable err.code across the principal error categories', () => {
    const locked = new AccessControl();
    locked.grant('u').readAny('post', ['*']);
    locked.lock();
    expect(grab(() => locked.grant('x')).code).toBe(ErrorCode.LOCKED);

    expect(grab(() => new AccessControl().grant('__proto__')).code).toBe(ErrorCode.RESERVED_NAME);
    expect(grab(() => new AccessControl().can('ghost').readAny('post')).code).toBe(
      ErrorCode.ROLE_NOT_FOUND
    );
    expect(grab(() => new AccessControl().setGrants(42 as any)).code).toBe(ErrorCode.INVALID_GRANT);

    const strict = new AccessControl({}, { policy: { strict: true } });
    strict.grant('u').readAny('post', ['*']);
    expect(grab(() => strict.can('u').action('frob', 'post').granted).code).toBe(
      ErrorCode.UNKNOWN_ACTION
    );
    expect(grab(() => strict.can('u').readAny('ghostres').granted).code).toBe(
      ErrorCode.UNKNOWN_RESOURCE
    );

    const ac = new AccessControl();
    ac.grant('u').where({ fn: 'x' }).readAny('post', ['*']);
    expect(grab(() => ac.can('u').readAny('post').granted).code).toBe(ErrorCode.ASYNC_REQUIRED);
  });

  test('request-derived strict messages do not leak the queried value', () => {
    const ac = new AccessControl({}, { policy: { strict: true } });
    ac.grant('u').readAny('post', ['*']);
    const e = grab(() => ac.can('u').readAny('topsecret-resource-name').granted);
    expect(e.message).not.toContain('topsecret-resource-name');
    expect(e.resource).toBe('topsecret-resource-name'); // available programmatically
  });

  // Each row: a trigger that throws, the expected err.code, and a dynamic value
  // that must be REDACTED from the default message but PRESENT in verbose mode.
  // This pins the code (kills `{ code }` → `{}`) and the safeErrors branch in one
  // place, across validation/roles/grants/AccessControl/condition.
  const strictAC = () => {
    const a = new AccessControl({}, { engine: { allowRegex: true }, policy: { strict: true } });
    a.grant('u').readAny('post', ['*']);
    return a;
  };
  const rows: Array<[string, ErrorCode, string, (ac: AccessControl) => unknown]> = [
    ['invalid name', ErrorCode.INVALID_NAME, 'bad name', (ac) => ac.grant('bad name')],
    ['reserved name', ErrorCode.RESERVED_NAME, '__proto__', (ac) => ac.grant('__proto__')],
    [
      'invalid possession',
      ErrorCode.INVALID_ACTION,
      'sideways',
      (ac) => ac.check({ role: 'u', resource: 'post', action: 'read:sideways' }).granted
    ],
    ['invalid query info', ErrorCode.INVALID_QUERY, 'number', (ac) => ac.check(42 as any).granted],
    [
      'invalid role definition',
      ErrorCode.INVALID_GRANT,
      'admin',
      (ac) => ac.setGrants({ admin: 'nope' } as any)
    ],
    [
      'role not found',
      ErrorCode.ROLE_NOT_FOUND,
      'ghostrole',
      (ac) => ac.can('ghostrole').readAny('post').granted
    ],
    ['self inheritance', ErrorCode.INVALID_INHERITANCE, 'u', (ac) => ac.extendRole('u', 'u')],
    [
      'unknown action',
      ErrorCode.UNKNOWN_ACTION,
      'frobnicate',
      (ac) => ac.can('u').action('frobnicate', 'post').granted
    ],
    [
      'unknown resource',
      ErrorCode.UNKNOWN_RESOURCE,
      'ghostres',
      (ac) => ac.can('u').readAny('ghostres').granted
    ],
    [
      'remove non-existing role',
      ErrorCode.ROLE_NOT_FOUND,
      'ghostrole',
      (ac) => ac.removeRoles('ghostrole')
    ]
  ];

  test.each(rows)('err.code + redaction: %s', (_label, code, value, trigger) => {
    const safeAc = strictAC();
    const e = grab(() => trigger(safeAc));
    expect(e.code).toBe(code); // kills `{ code }` → `{}`
    expect(e.message).not.toContain(value); // kills safe → false

    const verboseAc = new AccessControl(
      {},
      { engine: { safeErrors: false }, policy: { strict: true } }
    );
    verboseAc.grant('u').readAny('post', ['*']);
    const e2 = grab(() => trigger(verboseAc));
    expect(e2.code).toBe(code);
    expect(e2.message).toContain(value); // kills safe → true
  });

  test('condition error codes', () => {
    const ac = new AccessControl({}, { engine: { allowRegex: true } });
    ac.grant('u').where('$.name matches (a+)+').readAny('post', ['*']);
    expect(grab(() => ac.can('u', { name: 'a' }).readAny('post').granted).code).toBe(
      ErrorCode.UNSAFE_REGEX
    );

    const off = new AccessControl();
    off.grant('u').where('$.n matches x').readAny('post', ['*']);
    expect(grab(() => off.can('u', { n: 'x' }).readAny('post').granted).code).toBe(
      ErrorCode.REGEX_DISABLED
    );

    const fnAc = new AccessControl();
    fnAc.grant('u').where({ fn: 'nope' }).readAny('post', ['*']);
    return expect(fnAc.can('u').readAny('post').grantedAsync).rejects.toMatchObject({
      code: ErrorCode.UNKNOWN_CONDITION_FN
    });
  });

  test('deeply nested condition is rejected with INVALID_CONDITION', () => {
    let cond: any = ['$.x', '==', 1];
    for (let i = 0; i < 200; i++) cond = { and: [cond] };
    expect(grab(() => new AccessControl().grant('u').where(cond).readAny('post', ['*'])).code).toBe(
      ErrorCode.INVALID_CONDITION
    );
  });
});

describe('engine.errorCodePrefix', () => {
  test('prefixes every err.code across all surfaces; default leaves codes bare', async () => {
    const ac = new AccessControl({}, { engine: { errorCodePrefix: 'AC_', allowRegex: true } });
    ac.grant('u').readAny('post', ['*']);

    // validation / roles / lock / strict paths
    expect(grab(() => ac.grant('__proto__')).code).toBe('AC_RESERVED_NAME');
    expect(grab(() => ac.grant('bad name')).code).toBe('AC_INVALID_NAME');
    expect(grab(() => ac.can('ghost').readAny('post').granted).code).toBe('AC_ROLE_NOT_FOUND');
    expect(grab(() => ac.extendRole('u', 'u')).code).toBe('AC_INVALID_INHERITANCE');

    // compileCondition path (commit-time)
    expect(
      grab(() =>
        ac
          .grant('u')
          .where({ and: 'x' } as any)
          .readAny('post', ['*'])
      ).code
    ).toBe('AC_INVALID_CONDITION');

    // evaluator restamp path (sync): catastrophic regex
    const reg = new AccessControl({}, { engine: { errorCodePrefix: 'AC_', allowRegex: true } });
    reg.grant('u').where('$.x matches (a+)+').readAny('post', ['*']);
    expect(grab(() => reg.can('u', { x: 'a' }).readAny('post').granted).code).toBe(
      'AC_UNSAFE_REGEX'
    );

    // evaluator restamp path (async): unknown condition function
    const fn = new AccessControl({}, { engine: { errorCodePrefix: 'AC_' } });
    fn.grant('u').where({ fn: 'nope' }).readAny('post', ['*']);
    await expect(fn.can('u').readAny('post').grantedAsync).rejects.toMatchObject({
      code: 'AC_UNKNOWN_CONDITION_FN'
    });

    // lock
    ac.lock();
    expect(grab(() => ac.grant('x')).code).toBe('AC_LOCKED');

    // default: no prefix → bare enum value (back-compat)
    const plain = new AccessControl();
    expect(grab(() => plain.grant('__proto__')).code).toBe(ErrorCode.RESERVED_NAME);
  });
});

describe('during — hostile grants + fail-closed + code prefix', () => {
  const BAD_SYNTAX = {
    r: { post: { read: [{ attributes: ['*'], condition: ['$.now', 'during', 'T9999'] }] } }
  };
  const NEVER = {
    r: { post: { read: [{ attributes: ['*'], condition: ['$.now', 'during', 'D30 M2'] }] } }
  };

  test('hostile serialized grants throw coded at every load entry point', () => {
    // constructor (object form)
    expect(grab(() => new AccessControl(BAD_SYNTAX as any)).code).toBe(ErrorCode.INVALID_DTREXP);
    expect(grab(() => new AccessControl(NEVER as any)).code).toBe(ErrorCode.DTREXP_NEVER_MATCHES);
    // setGrants
    expect(grab(() => new AccessControl().setGrants(BAD_SYNTAX as any)).code).toBe(
      ErrorCode.INVALID_DTREXP
    );
    // flat grants-list form
    const row = {
      role: 'r',
      resource: 'post',
      action: 'read',
      possession: 'any',
      attributes: ['*'],
      condition: ['$.now', 'during', 'T9999']
    };
    expect(grab(() => new AccessControl([row] as any)).code).toBe(ErrorCode.INVALID_DTREXP);
  });

  test('tryCan() fails closed on an eval-time dtrexp throw (uncompiled hostile leaf)', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*']);
    // sneak an uncompiled bad leaf directly into the live model (bypasses
    // commit validation) — the eval-time throw must fail closed through tryCan().
    (ac as any)._grants.u.post.read[0].condition = ['$.now', 'during', 'T9999'];
    expect(ac.tryCan('u').readAny('post').granted).toBe(false);
    // and can() surfaces the coded error
    expect(grab(() => ac.can('u').readAny('post').granted).code).toBe(ErrorCode.INVALID_DTREXP);
  });

  test('engine.errorCodePrefix prefixes both new codes (commit + eval paths)', () => {
    const ac = new AccessControl({}, { engine: { errorCodePrefix: 'AC_' } });
    expect(grab(() => ac.grant('u').during('T9999').readAny('post', ['*'])).code).toBe(
      'AC_INVALID_DTREXP'
    );
    expect(grab(() => ac.grant('u').during('D30 M2').readAny('post', ['*'])).code).toBe(
      'AC_DTREXP_NEVER_MATCHES'
    );
    // eval-path restamp: uncompiled hostile leaf hits getDTRExp at check time
    ac.grant('u').readAny('post', ['*']);
    (ac as any)._grants.u.post.read[0].condition = ['$.now', 'during', 'T9999'];
    expect(grab(() => ac.can('u').readAny('post').granted).code).toBe('AC_INVALID_DTREXP');
  });
});

describe('an explicit empty attribute list never widens to everything', () => {
  // `attributes: []` means "no attributes" on every authoring path. The
  // object form used to turn it into ['*'] and grant everything — a
  // privilege-escalation shape for a rule loaded from a data store.
  const info = { role: 'u', resource: 'r', action: 'read:any', attributes: [] as string[] };

  const paths: Array<[string, () => AccessControl]> = [
    [
      'object form, ac.grant(info)',
      () => {
        const ac = new AccessControl();
        ac.grant({ ...info });
        return ac;
      }
    ],
    [
      'object form, chained access.grant(info)',
      () => {
        const ac = new AccessControl();
        ac.grant('seed')
          .readAny('seed')
          .grant({ ...info });
        return ac;
      }
    ],
    [
      'builder, readAny(r, [])',
      () => {
        const ac = new AccessControl();
        ac.grant('u').readAny('r', []);
        return ac;
      }
    ],
    ['grants list', () => new AccessControl([{ ...info }])],
    [
      'grants object',
      () => new AccessControl({ u: { r: { read: [{ possession: 'any', attributes: [] }] } } })
    ]
  ];

  test.each(paths)('%s: stores [] and denies', (_, make) => {
    const ac = make();
    const permission = ac.can('u').readAny('r');
    expect(permission.granted).toBe(false);
    expect(permission.attributes).toEqual([]);
  });

  test('the object form with attributes omitted still grants everything', () => {
    const ac = new AccessControl();
    ac.grant({ role: 'u', resource: 'r', action: 'read:any' });
    expect(ac.can('u').readAny('r').attributes).toEqual(['*']);
  });

  test('deny mirror: a deny of [] denies nothing; an omitted list denies all', () => {
    const none = new AccessControl();
    none.grant('u').readAny('r');
    none.deny({ role: 'u', resource: 'r', action: 'read:any', attributes: [] });
    expect(none.can('u').readAny('r').granted).toBe(true);

    const all = new AccessControl();
    all.grant('u').readAny('r');
    all.deny({ role: 'u', resource: 'r', action: 'read:any' });
    expect(all.can('u').readAny('r').granted).toBe(false);
  });
});

describe('an invalid context.tz is an AccessControlError, never a raw RangeError', () => {
  const make = (engine = {}) => {
    const ac = new AccessControl({}, { engine });
    ac.grant('u').where('$.now.hour >= 0').readAny('post');
    return ac;
  };

  test('can() throws INVALID_QUERY with the RangeError as its cause; the value stays out', () => {
    const err = grab(() => make().can('u', { tz: 'Mars/Phobos' }).readAny('post').granted);
    expect(err).toBeInstanceOf(AccessControlError);
    expect(err.code).toBe(ErrorCode.INVALID_QUERY);
    expect(err.cause).toBeInstanceOf(RangeError);
    expect(err.message).toContain('context.tz');
    expect(err.message).not.toContain('Mars/Phobos');
  });

  test('the code takes engine.errorCodePrefix; tryCan() denies instead of throwing', () => {
    expect(
      grab(
        () =>
          make({ errorCodePrefix: 'AC_' }).can('u', { tz: 'Mars/Phobos' }).readAny('post').granted
      ).code
    ).toBe('AC_INVALID_QUERY');
    expect(make().tryCan('u', { tz: 'Mars/Phobos' }).readAny('post').granted).toBe(false);
  });

  test('the async path surfaces the same error', async () => {
    const ac = make();
    let err: any;
    try {
      await ac.can('u', { tz: 'Mars/Phobos' }).readAny('post').grantedAsync;
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(AccessControlError);
    expect(err.code).toBe(ErrorCode.INVALID_QUERY);
  });
});

describe('the chain .attributes() list is kept at commit, never widened to everything', () => {
  // `.attributes(list)` was overwritten by the commit's own parameter, so a
  // grant written as `.attributes(['title']).readAny('post')` stored ['*'].
  test.each<[string, (ac: AccessControl) => void]>([
    ['ac.grant(role)', (ac) => ac.grant('u').attributes(['title']).readAny('post')],
    [
      'chained access.grant(role)',
      (ac) => ac.grant('seed').readAny('seed').grant('u').attributes(['title']).readAny('post')
    ],
    ['generic action()', (ac) => ac.grant('u').attributes(['title']).action('read', 'post')],
    [
      'object form without an action',
      (ac) => ac.grant({ role: 'u', attributes: ['title'] }).readAny('post')
    ]
  ])('%s: grants only the listed attributes', (_, author) => {
    const ac = new AccessControl();
    author(ac);
    expect(ac.can('u').readAny('post').attributes).toEqual(['title']);
  });

  test('an attributes argument wins over the chain list', () => {
    const ac = new AccessControl();
    ac.grant('u').attributes(['title']).readAny('post', ['body']);
    expect(ac.can('u').readAny('post').attributes).toEqual(['body']);
  });

  test('the list applies to the next action only', () => {
    const ac = new AccessControl();
    ac.grant('u').attributes(['title']).readAny('post').updateAny('post');
    expect(ac.can('u').readAny('post').attributes).toEqual(['title']);
    expect(ac.can('u').updateAny('post').attributes).toEqual(['*']);
  });

  test('a fulfilled object form does not pass its list to a chained action', () => {
    const ac = new AccessControl();
    ac.grant({ role: 'u', resource: 'post', action: 'read:any', attributes: ['title'] }).updateAny(
      'post'
    );
    expect(ac.can('u').readAny('post').attributes).toEqual(['title']);
    expect(ac.can('u').updateAny('post').attributes).toEqual(['*']);
  });

  test('deny mirror: the list is what is denied; a chained deny still denies all', () => {
    const some = new AccessControl();
    some.grant('u').readAny('post');
    some.deny('u').attributes(['secret']).readAny('post');
    expect(some.can('u').readAny('post').attributes).toEqual(['*', '!secret']);

    const all = new AccessControl();
    all.grant('u').readAny('post').deny('u').readAny('post');
    expect(all.can('u').readAny('post').granted).toBe(false);
  });
});

describe('every condition compile error and lock() carry a code; safeErrors hides the expression', () => {
  // Each expression embeds a marker so a leak into the message is visible.
  const BAD: Array<string | unknown[]> = [
    "$.s == 'SECRET",
    '$.x in [SECRET, b',
    '$.SECRET ==',
    '$.x SECRET 1',
    '$.x in [SECRET,,b]',
    '$.v between [SECRET]',
    '$.v between [5, 2]',
    '$.ip cidr 10.0.0/8',
    '$.ip cidr 10.0.0.0/99',
    '$.ip cidr 10.0.0.256',
    '$.SECRET not in',
    ['$.SECRET', '=='],
    ['$.x', 'SECRET', 1],
    ['$.x', 'between', [9, 1]]
  ];
  const author = (engine: object, cond: unknown) => () =>
    new AccessControl({}, { engine })
      .grant('u')
      .where(cond as any)
      .readAny('post');

  test.each(BAD.map((c) => [JSON.stringify(c), c]))('%s', (_, cond) => {
    const safe = grab(author({ errorCodePrefix: 'AC_' }, cond));
    expect(safe).toBeInstanceOf(AccessControlError);
    expect(safe.code).toBe('AC_INVALID_CONDITION');
    expect(safe.message).not.toMatch(/SECRET|10\.0\.0|\b9\b|\[5, 2\]/);
    const verbose = grab(author({ safeErrors: false }, cond));
    expect(verbose.code).toBe(ErrorCode.INVALID_CONDITION);
    // these two messages name no value, so there is nothing to show
    const named = !['$.x in [SECRET,,b]', '$.v between [SECRET]'].includes(cond as string);
    expect(verbose.message.includes('Got:')).toBe(named);
    if (!named) expect(verbose.message).toMatch(/^[^!]*\.$/);
  });

  test('a condition of no known shape is coded and shown only with safeErrors off', () => {
    const safe = grab(author({ errorCodePrefix: 'AC_' }, 4242));
    expect(safe.code).toBe('AC_INVALID_CONDITION');
    expect(safe.message).toBe('Invalid condition.');
    expect(grab(author({ safeErrors: false }, 4242)).message).toContain('Got: 4242');
  });

  test('a condition in a grants object takes the same safety', () => {
    const grants = (cond: string): any => ({
      u: { post: { read: [{ possession: 'any', attributes: ['*'], condition: cond }] } }
    });
    const safe = grab(() => new AccessControl(grants('$.x SECRET 1')));
    expect(safe.code).toBe(ErrorCode.INVALID_CONDITION);
    expect(safe.message).not.toContain('SECRET');
    const verbose = grab(
      () => new AccessControl(grants('$.x SECRET 1'), { engine: { safeErrors: false } })
    );
    expect(verbose.message).toContain('SECRET');
  });

  test('require() gates take the same code and safety', () => {
    const err = grab(() => new AccessControl().require('$.x SECRET 1'));
    expect(err.code).toBe(ErrorCode.INVALID_CONDITION);
    expect(err.message).not.toContain('SECRET');
  });

  test('lock() on an empty model throws INVALID_GRANT, with the prefix', () => {
    expect(grab(() => new AccessControl().lock()).code).toBe(ErrorCode.INVALID_GRANT);
    expect(
      grab(() => new AccessControl({}, { engine: { errorCodePrefix: 'AC_' } }).lock()).code
    ).toBe('AC_INVALID_GRANT');
  });
});
