/**
 *  Test Suite: property-based invariants (seeded fuzzer).
 *
 *  Coverage/mutation prove the *written* branches behave; they say nothing about
 *  emergent properties across arbitrary policies. This suite generates thousands
 *  of random grant models from a fixed seed (deterministic & reproducible — no
 *  external dependency) and asserts the safety invariants an authorization
 *  engine must never violate:
 *
 *    1. Determinism            — same query ⇒ same answer.
 *    2. cascade (any ⊆ own)   — an `any` grant also satisfies an `own` check.
 *    3. Multi-role = union     — checking [a,b] equals unioning a and b.
 *    4. Serialization round-trip — getGrantsList ↔ rebuild is decision-stable.
 *    5. getGrants immutability — the returned clone cannot alter the engine.
 *    6. Deny monotonicity      — adding a deny rule never grants more.
 *    7. Require monotonicity   — adding a require() gate never grants more.
 *    8. Filter idempotence     — filtering filtered data is a fixed point.
 *
 *  A failure here is a real authorization defect, surfaced with its seed.
 */

import type { IGrantsList } from '../src/index.js';
import { AccessControl } from '../src/index.js';
import { getDTRExp } from '../src/utils/index.js';

// ----- deterministic RNG (mulberry32) -----
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const ROLES = ['ra', 'rb', 'rc'];
const RESOURCES = ['doc', 'file', 'img'];
const ACTIONS = ['read', 'update', 'manage'];
const POSSESSIONS = ['any', 'own'] as const;
const ATTRS = ['id', 'name', 'email', 'secret', 'meta'];
const PROBE = (): Record<string, number> => ({ id: 1, name: 1, email: 1, secret: 1, meta: 1 });

const pick = <T>(r: () => number, arr: readonly T[]): T => arr[(r() * arr.length) | 0];

function randomAttrs(r: () => number): string[] {
  if (r() < 0.35) return ['*'];
  const out: string[] = [];
  for (const a of ATTRS) if (r() < 0.5) out.push(a);
  if (r() < 0.4) out.push(`!${pick(r, ATTRS)}`); // a negation
  return out;
}

interface Model {
  ac: AccessControl;
  list: IGrantsList;
}

// lenient strict so every query in the matrix yields a decision (not a typo
// throw); we are testing the resolution algebra, not strict-mode guards.
const LENIENT = { policy: { strict: false } } as const;
const makeAC = (grants?: IGrantsList) =>
  grants ? new AccessControl(grants, LENIENT) : new AccessControl({}, LENIENT);

/** Builds a random (no-condition, no-ownerField) policy. */
function buildModel(seed: number, opts: { deny?: boolean } = {}): Model {
  const allowDeny = opts.deny !== false;
  const r = rng(seed);
  const ac = makeAC();
  const ops = 2 + ((r() * 7) | 0);
  for (let i = 0; i < ops; i++) {
    const role = pick(r, ROLES);
    const res = pick(r, RESOURCES);
    const act = pick(r, ACTIONS);
    const poss = pick(r, POSSESSIONS);
    const attrs = randomAttrs(r);
    const a = allowDeny && r() < 0.3 ? ac.deny(role) : ac.grant(role);
    a.action(`${act}:${poss}`, res, attrs);
  }
  // acyclic inheritance only (ra ← rb ← rc), so no cross-inheritance throws;
  // both roles must already have grants for extendRole to apply.
  if (r() < 0.5 && ac.hasRole('rb') && ac.hasRole('ra')) ac.extendRole('rb', 'ra');
  if (r() < 0.5 && ac.hasRole('rc') && ac.hasRole('rb')) ac.extendRole('rc', 'rb');
  return { ac, list: ac.getGrantsList() };
}

/** Allowed attribute keys for one check, derived from the actual filter output. */
function allowedKeys(
  ac: AccessControl,
  role: string | string[],
  res: string,
  spec: string
): string[] {
  const out = ac.can(role).action(spec, res).filter(PROBE()) as Record<string, unknown>;
  return Object.keys(out).sort();
}

/** Full decision matrix (single-role) used for stability comparisons. */
function decisionMatrix(ac: AccessControl): Record<string, { g: boolean; keys: string[] }> {
  const m: Record<string, { g: boolean; keys: string[] }> = {};
  for (const role of ROLES) {
    for (const res of RESOURCES) {
      for (const act of ACTIONS) {
        for (const poss of POSSESSIONS) {
          const spec = `${act}:${poss}`;
          const perm = ac.can(role).action(spec, res);
          m[`${role}|${res}|${spec}`] = { g: perm.granted, keys: allowedKeys(ac, role, res, spec) };
        }
      }
    }
  }
  return m;
}

const SEEDS = Array.from({ length: 400 }, (_, i) => i * 2654435761 + 1);
const subset = (a: string[], b: string[]) => a.every((x) => b.includes(x));

describe('Invariants (seeded fuzz, 400 models)', () => {
  test('1. determinism — identical queries give identical answers', () => {
    for (const seed of SEEDS) {
      const { ac } = buildModel(seed);
      const m1 = decisionMatrix(ac);
      const m2 = decisionMatrix(ac);
      expect(m2).toEqual(m1);
    }
  });

  test('2. cascade — an `any` grant satisfies an `own` check (any ⊆ own)', () => {
    // With no ownerField, an `own` query applies both `own` and `any` rules,
    // while an `any` query applies only `any` rules. So whatever `any` allows,
    // `own` must also allow: allowedKeys(any) ⊆ allowedKeys(own).
    for (const seed of SEEDS) {
      const { ac } = buildModel(seed, { deny: false }); // pure grant cascade
      for (const role of ROLES) {
        for (const res of RESOURCES) {
          for (const act of ACTIONS) {
            const own = allowedKeys(ac, role, res, `${act}:own`);
            const any = allowedKeys(ac, role, res, `${act}:any`);
            if (!subset(any, own)) throw new Error(`cascade violated @seed ${seed}`);
            expect(subset(any, own)).toBe(true);
          }
        }
      }
    }
  });

  test('3. multi-role check equals the union of single-role checks', () => {
    for (const seed of SEEDS) {
      const { ac } = buildModel(seed);
      for (const res of RESOURCES) {
        for (const act of ACTIONS) {
          const spec = `${act}:any`;
          const a = allowedKeys(ac, 'ra', res, spec);
          const b = allowedKeys(ac, 'rb', res, spec);
          const union = [...new Set([...a, ...b])].sort();
          const multi = allowedKeys(ac, ['ra', 'rb'], res, spec);
          expect(multi).toEqual(union);
        }
      }
    }
  });

  test('4. serialization round-trip is decision-stable', () => {
    for (const seed of SEEDS) {
      const { ac, list } = buildModel(seed);
      const rebuilt = makeAC(list);
      expect(decisionMatrix(rebuilt)).toEqual(decisionMatrix(ac));
      // and the list itself round-trips to an equal list
      expect(rebuilt.getGrantsList()).toEqual(list);
    }
  });

  test('5. getGrants() returns an inert frozen clone', () => {
    for (const seed of SEEDS.slice(0, 100)) {
      const { ac } = buildModel(seed);
      const before = decisionMatrix(ac);
      const g = ac.getGrants() as any;
      expect(Object.isFrozen(g)).toBe(true);
      try {
        // try to widen every rule we can reach; frozen ⇒ throws, which is fine
        for (const role of Object.keys(g)) {
          for (const resOrExt of Object.keys(g[role])) {
            const node = g[role][resOrExt];
            if (Array.isArray(node)) continue;
            for (const action of Object.keys(node)) {
              for (const rule of node[action]) rule.attributes.push('*');
            }
          }
        }
      } catch {
        /* expected: frozen */
      }
      expect(decisionMatrix(ac)).toEqual(before);
    }
  });

  test('6. deny monotonicity — adding a deny never widens any decision', () => {
    for (const seed of SEEDS) {
      const { ac, list } = buildModel(seed);
      const before = decisionMatrix(ac);
      const r = rng(seed ^ 0x9e3779b9);
      const widened = makeAC(list);
      widened
        .deny(pick(r, ROLES))
        .action(`${pick(r, ACTIONS)}:any`, pick(r, RESOURCES), [pick(r, ATTRS)]);
      const after = decisionMatrix(widened);
      for (const k of Object.keys(after)) {
        expect(subset(after[k].keys, before[k].keys)).toBe(true);
        if (after[k].g) expect(before[k].g).toBe(true); // granted-after ⟹ granted-before
      }
    }
  });

  test('7. require monotonicity — adding a gate never widens any decision', () => {
    const ctx = { x: 1 };
    for (const seed of SEEDS) {
      const { ac, list } = buildModel(seed);
      const before = decisionMatrix(ac);
      const gated = makeAC(list);
      // a gate that sometimes passes, sometimes not, but can only ever restrict
      gated.require(seed % 2 === 0 ? '$.x == 1' : '$.x == 999');
      for (const role of ROLES) {
        for (const res of RESOURCES) {
          for (const act of ACTIONS) {
            for (const poss of POSSESSIONS) {
              const spec = `${act}:${poss}`;
              const perm = gated.can(role, ctx).action(spec, res);
              const keys = Object.keys(perm.filter(PROBE()) as Record<string, unknown>);
              const key = `${role}|${res}|${spec}`;
              expect(subset(keys, before[key].keys)).toBe(true);
              if (perm.granted) expect(before[key].g).toBe(true);
            }
          }
        }
      }
    }
  });

  test('8. filter idempotence — filtering filtered data is a fixed point', () => {
    for (const seed of SEEDS) {
      const { ac } = buildModel(seed);
      for (const role of ROLES) {
        for (const res of RESOURCES) {
          const perm = ac.can(role).action('read:any', res);
          const once = perm.filter(PROBE());
          const twice = perm.filter(once);
          expect(twice).toEqual(once);
        }
      }
    }
  });
});

describe('Invariant: a during schedule only restricts, never grants', () => {
  test('for any instant, scheduled ⊆ unscheduled (same attributes when granted)', () => {
    const BH = 'T0900:1800 E1:5';
    const plain = new AccessControl();
    plain.grant('u').updateAny('doc', ['id', 'name']);
    const scheduled = new AccessControl();
    scheduled.grant('u').during(BH).updateAny('doc', ['id', 'name']);

    // a deterministic spread of instants: weekday/weekend, in/out of hours, boundaries
    const instants = [
      '2026-07-20T09:00:00Z', // Mon window start (inclusive)
      '2026-07-20T10:00:00Z', // Mon in-window
      '2026-07-20T17:59:00Z', // Mon last covered minute
      '2026-07-20T18:00:00Z', // Mon window end (exclusive)
      '2026-07-20T03:00:00Z', // Mon pre-window
      '2026-07-18T10:00:00Z', // Saturday
      '2026-07-19T23:59:00Z' // Sunday night
    ];
    for (const now of instants) {
      const ctx = { now, tz: 'UTC' };
      const p = plain.can('u', ctx).updateAny('doc');
      const s = scheduled.can('u', ctx).updateAny('doc');
      // restriction: scheduled granted ⇒ plain granted (never the reverse)
      if (s.granted) {
        expect(p.granted).toBe(true);
        expect(s.attributes).toEqual(p.attributes);
      }
      // and the schedule itself decides exactly per dtrexp coverage
      expect(s.granted).toBe(getDTRExp(BH).covers(now, { tz: 'UTC' }));
    }
  });
});
