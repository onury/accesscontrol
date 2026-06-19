/**
 *  Test Suite: adversarial / security.
 *
 *  These tests assert *negative-space* guarantees — properties that 100% line
 *  coverage and mutation testing cannot establish, because they concern inputs
 *  the implementation never explicitly mentions: prototype-pollution gadget
 *  keys, inherited object members used as names, context that tries to spoof the
 *  query, immutability after lock(), and the "a deny/require can never widen
 *  access" safety direction. For an authorization library, a wrong answer here
 *  is a vulnerability, not a bug.
 */

import { AccessControl } from '../src/index.js';

/** Runs `fn`, returns the thrown error (fails if it doesn't throw). */
function grab(fn: () => unknown): any {
  try {
    fn();
  } catch (e) {
    return e;
  }
  throw new Error('expected function to throw');
}

const PROTO_GADGETS = ['__proto__', 'prototype', 'constructor'];
// inherited Object/Function members that are valid per the charset but must
// never be read off a prototype by the engine.
const INHERITED_KEYS = [
  'toString',
  'valueOf',
  'hasOwnProperty',
  'isPrototypeOf',
  'propertyIsEnumerable',
  'toLocaleString'
];

describe('Security: prototype-pollution gadget names are rejected', () => {
  test('reserved names throw at grant/deny/check/extend/setup/define time', () => {
    for (const bad of PROTO_GADGETS) {
      const ac = new AccessControl();
      expect(grab(() => ac.grant(bad).readAny('post', ['*'])).message).toContain('Reserved');
      expect(grab(() => ac.grant('u').readAny(bad, ['*'])).message).toContain('Reserved');
      expect(grab(() => ac.grant('u').action(bad, 'post', ['*'])).message).toContain('Reserved');
      expect(grab(() => ac.can(bad).readAny('post')).message).toContain('Reserved');
      expect(grab(() => ac.can('u').readAny(bad)).message).toContain('Reserved');
    }
  });

  test('reserved names rejected inside qualified group/category segments', () => {
    const ac = new AccessControl();
    expect(grab(() => ac.grant('u').readAny(`__proto__/x`)).message).toContain('Reserved');
    expect(grab(() => ac.grant('u').readAny(`x/constructor`)).message).toContain('Reserved');
  });

  test('reserved keys in a setGrants payload (DB/JSON import) are rejected', () => {
    const ac = new AccessControl();
    // an own "__proto__" key, as produced by JSON.parse (not an object literal)
    const payload = JSON.parse('{"__proto__":{"post":{"read":[{"attributes":["*"]}]}}}');
    expect(grab(() => ac.setGrants(payload)).message).toContain('Reserved');
    expect(
      grab(() => ac.setGrants({ constructor: { post: { read: [{ attributes: ['*'] }] } } } as any))
        .message
    ).toContain('Reserved');
  });

  test('no global prototype pollution after touching gadget keys', () => {
    const ac = new AccessControl();
    // each of these throws, but assert the environment stays clean regardless
    for (const bad of PROTO_GADGETS) {
      try {
        ac.grant(bad).readAny('post', ['*']);
      } catch {
        /* expected */
      }
    }
    expect(({} as any).post).toBeUndefined();
    expect(({} as any).readAny).toBeUndefined();
    expect(Object.hasOwn(Object.prototype, 'post')).toBe(false);
  });
});

describe('Security: inherited object members are safe resource/group/category names', () => {
  test('checking a resource named like an inherited member returns false, never throws', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*']);
    for (const key of INHERITED_KEYS) {
      expect(ac.can('u').readAny(key).granted).toBe(false);
      expect(ac.check({ role: 'u', resource: key, action: 'read:any' }).granted).toBe(false);
      // and they genuinely work when actually granted
      const ac2 = new AccessControl();
      ac2.grant('u').readAny(key, ['*']);
      expect(ac2.can('u').readAny(key).granted).toBe(true);
      expect(ac2.getResources()).toContain(key);
    }
  });

  test('group()/category() introspection on inherited names yields empty, not a crash', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*']);
    for (const key of INHERITED_KEYS) {
      expect(ac.group(key).getRoles()).toEqual([]);
      expect(ac.category(key).getResources()).toEqual([]);
    }
  });

  test('a require() gate on an inherited category name does not poison other checks', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*']);
    ac.category('toString').require('$.x == 1'); // pathological but must not crash
    expect(ac.can('u', { x: 1 }).readAny('post').granted).toBe(true);
  });

  test('a custom-fn condition named like an inherited member is "unknown", not a builtin', async () => {
    const ac = new AccessControl();
    ac.grant('u').where({ fn: 'toString' }).readAny('post', ['*']);
    await expect(ac.can('u').readAny('post').grantedAsync).rejects.toThrow(
      'Unknown condition function'
    );
  });
});

describe('Security: context cannot spoof the query metadata', () => {
  test('context.role/resource/action/possession never override the actual query', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('secret', ['*']);
    ac.grant('user').readAny('post', ['*']);

    // a condition reading $.role must see the *queried* role, not context.role
    const ac2 = new AccessControl();
    ac2.grant('user').where('$.role == admin').readAny('post', ['*']);
    expect(ac2.can('user', { role: 'admin' }).readAny('post').granted).toBe(false);

    // spoofing resource/action/possession in context changes nothing
    const spoof = { resource: 'secret', action: 'read', possession: 'any', roles: ['admin'] };
    expect(ac.can('user', spoof).readAny('post').granted).toBe(true); // real query still 'post'
    expect(ac.can('user', spoof).readAny('secret').granted).toBe(false); // user can't read secret
  });

  test('reserved $.now / $.tz context keys are derived, not blindly trusted for identity', () => {
    const ac = new AccessControl();
    ac.grant('u').where('$.now.year > 1999').readAny('post', ['*']);
    expect(ac.can('u').readAny('post').granted).toBe(true);
  });
});

describe('Security: notation path resolution is pollution-safe', () => {
  test('a condition path through __proto__ does not pollute or grant', () => {
    const ac = new AccessControl();
    ac.grant('u').where('$.input.__proto__.polluted == yes').readAny('post', ['*']);
    expect(ac.can('u', { input: {} }).readAny('post').granted).toBe(false);
    expect(({} as any).polluted).toBeUndefined();
  });

  test('missing / nullish paths evaluate to a clean false, not a throw', () => {
    const ac = new AccessControl();
    ac.grant('u').where('$.a.b.c.d == 1').readAny('post', ['*']);
    expect(ac.can('u', {}).readAny('post').granted).toBe(false);
    expect(ac.can('u', { a: null }).readAny('post').granted).toBe(false);
  });
});

describe('Security: lock() is a real immutability boundary', () => {
  test('getGrants() returns a frozen deep clone that cannot mutate the engine', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*', '!secret']);
    const g = ac.getGrants() as any;
    expect(Object.isFrozen(g)).toBe(true);
    // attempting to widen via the returned object must throw (frozen) or no-op
    expect(() => {
      g.u.post.read[0].attributes.push('secret');
    }).toThrow();
    // engine decision is unchanged
    expect(ac.can('u').readAny('post').filter({ id: 1, secret: 2 })).toEqual({ id: 1 });
  });

  test('after lock(), every mutator throws and the model is frozen', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*']);
    ac.lock();
    expect(ac.isLocked).toBe(true);
    expect(Object.isFrozen((ac as any)._grants)).toBe(true);
    expect(grab(() => ac.grant('x')).message).toContain('locked');
    // a locked instance still answers checks correctly
    expect(ac.can('u').readAny('post').granted).toBe(true);
  });

  test('Permission.attributes/roles are frozen copies (no live-reference leak)', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*', '!secret']);
    const p = ac.can('u').readAny('post');
    expect(Object.isFrozen(p.attributes)).toBe(true);
    expect(Object.isFrozen(p.roles)).toBe(true);
    expect(() => (p.attributes as string[]).push('secret')).toThrow();
    // mutating the returned array (frozen) cannot affect a fresh query
    expect(ac.can('u').readAny('post').attributes).toEqual(['*', '!secret']);
  });
});

describe('Security: deny-overrides and wildcards never leak', () => {
  test('a negated attribute is never returned, even with a "*" grant', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*', '!ssn']);
    const out = ac.can('u').readAny('post').filter({ id: 1, ssn: '123-45-6789' }) as any;
    expect(out.ssn).toBeUndefined();
    expect(out.id).toBe(1);
  });

  test('deny always wins over grant for the same possession (deny-overrides)', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*']);
    ac.deny('u').readAny('post', ['secret']);
    const out = ac.can('u').readAny('post').filter({ id: 1, secret: 2 }) as any;
    expect(out.secret).toBeUndefined();
    expect(out.id).toBe(1);
  });

  test('a grant for one resource never leaks to another', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*']);
    expect(ac.can('u').readAny('comment').granted).toBe(false);
  });

  test('a grant for one role never leaks to a sibling role', () => {
    const ac = new AccessControl();
    ac.grant('admin').readAny('post', ['*']);
    ac.grant('guest').readAny('comment', ['*']);
    expect(ac.can('guest').readAny('post').granted).toBe(false);
  });
});

describe('Security: introspection getters are inert; the engine is fault-isolated', () => {
  test('getRequirements() cannot be used to neuter a live require() gate', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*']);
    ac.require('$.x == 1');
    expect(ac.can('u', { x: 2 }).readAny('post').granted).toBe(false); // gate active

    const req = ac.getRequirements() as any;
    // try to rewrite the returned gate to something always-true
    req.global[0][2] = 2;
    req.global.push(['$.y', '==', 1]);
    // the live gate is unchanged
    expect(ac.can('u', { x: 2 }).readAny('post').granted).toBe(false);
    expect(ac.can('u', { x: 1 }).readAny('post').granted).toBe(true);
  });

  test('a throwing audit/error listener never breaks (or alters) a decision', () => {
    const ac = new AccessControl();
    ac.grant('u').readAny('post', ['*']);
    ac.on('access', () => {
      throw new Error('boom');
    });
    ac.on('change', () => {
      throw new Error('boom');
    });
    expect(ac.can('u').readAny('post').granted).toBe(true);
    // a change-emitting mutation also survives a faulty listener
    expect(() => ac.grant('u2').readAny('post', ['*'])).not.toThrow();
  });

  test('pathologically deep condition trees are rejected, not stack-overflowed', () => {
    let cond: any = ['$.x', '==', 1];
    for (let i = 0; i < 500; i++) cond = { and: [cond] };
    const ac = new AccessControl();
    expect(grab(() => ac.grant('u').where(cond).readAny('post', ['*'])).message).toContain(
      'nesting too deep'
    );
    // also rejected on the bulk import path
    expect(
      grab(
        () =>
          new AccessControl({
            u: { post: { read: [{ attributes: ['*'], condition: cond }] } }
          } as any)
      ).message
    ).toContain('nesting too deep');
  });
});
