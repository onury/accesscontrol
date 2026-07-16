/**
 *  Test Suite: DB serialization & round-trip parity (P10, §5.0).
 *  getGrantsList() ⇄ object form; both list & object inputs; getRequirements().
 */

import { AccessControl } from '../src/index.js';

/** Builds a feature-rich AC used across the round-trip tests. */
function buildAc(): AccessControl {
  const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
  ac.grant('user').readOwn('profile', ['*', '!password']);
  ac.grant('user').updateOwn('profile', ['email']);
  ac.grant('editor').where('$.article.status == draft').action('publish', 'article', ['*']);
  ac.deny('editor').readAny('article', ['secret']);
  ac.grant('admin').readAny('media/photo', ['*']); // qualified resource
  ac.extendRole('admin', 'editor');
  return ac;
}

describe('Test Suite: serialization (P10)', () => {
  test('getGrantsList() emits rows + inheritance rows', () => {
    const ac = buildAc();
    const list = ac.getGrantsList();
    expect(Array.isArray(list)).toBe(true);

    // a rule row carries role/resource/action/possession/attributes
    const readOwn = list.find(
      (r) => r.role === 'user' && r.resource === 'profile' && r.action === 'read'
    );
    expect(readOwn).toMatchObject({ possession: 'own', attributes: ['*', '!password'] });

    // a deny row preserves effect
    const denyRow = list.find((r) => r.role === 'editor' && r.effect === 'deny');
    expect(denyRow).toMatchObject({ resource: 'article', action: 'read', possession: 'any' });

    // a conditional grant preserves the compiled condition
    const publishRow = list.find((r) => r.action === 'publish');
    expect(publishRow?.condition).toEqual(['$.article.status', '==', 'draft']);

    // an inheritance row
    const extendRow = list.find((r) => r.$extend !== undefined);
    expect(extendRow).toMatchObject({ role: 'admin', $extend: ['editor'] });
  });

  test('object → list → object round-trips identically', () => {
    const ac = buildAc();
    const objectForm = ac.getGrants();
    const list = ac.getGrantsList();

    const restored = new AccessControl(list, { policy: { ownerField: 'ownerId' } });
    expect(restored.getGrants()).toEqual(objectForm);
  });

  test('list → object → list round-trips identically', () => {
    const ac = buildAc();
    const list1 = ac.getGrantsList();
    const restored = new AccessControl(list1, { policy: { ownerField: 'ownerId' } });
    const list2 = restored.getGrantsList();
    // order-independent comparison
    expect([...list2].sort(byRow)).toEqual([...list1].sort(byRow));
  });

  test('restored model behaves identically (checks match)', () => {
    const ac = buildAc();
    const restored = new AccessControl(ac.getGrantsList(), {
      policy: { ownerField: 'ownerId' }
    });

    const ctx = { article: { status: 'draft' } };
    expect(restored.can('editor', ctx).action('publish', 'article').granted).toBe(
      ac.can('editor', ctx).action('publish', 'article').granted
    );
    expect(
      restored.can('user', { user: { id: 1 }, profile: { ownerId: 1 } }).readOwn('profile').granted
    ).toBe(true);
    // inherited (admin extends editor) + deny carried over
    expect(
      restored.can('admin', { article: { status: 'draft' } }).action('publish', 'article').granted
    ).toBe(true);
    expect(restored.can('admin').readAny('media/photo').granted).toBe(true);
  });

  test('both list and object inputs are accepted by the constructor', () => {
    const ac = buildAc();
    const fromObject = new AccessControl(ac.getGrants(), { policy: { ownerField: 'ownerId' } });
    const fromList = new AccessControl(ac.getGrantsList(), { policy: { ownerField: 'ownerId' } });
    expect(fromObject.getGrants()).toEqual(fromList.getGrants());
  });

  test('getRequirements() serializes gates by scope (compiled)', () => {
    const ac = new AccessControl();
    ac.require('$.env == prod');
    ac.category('billing').require('$.ip == trusted');
    ac.resource('billing/invoice').require('$.mfa == true');
    const reqs = ac.getRequirements();
    expect(reqs.global).toEqual([['$.env', '==', 'prod']]);
    expect(reqs.categories.billing).toEqual([['$.ip', '==', 'trusted']]);
    expect(reqs.resources['billing/invoice']).toEqual([['$.mfa', '==', true]]);
  });

  test('empty model serializes to an empty list', () => {
    expect(new AccessControl().getGrantsList()).toEqual([]);
  });
});

describe('Test Suite: vocabulary + snapshot/restore round-trip', () => {
  /** AC with grants, gates in all three scopes, and grouped vocabulary. */
  function buildFull(): AccessControl {
    const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
    ac.setup({
      roles: { admins: ['admin', 'moderator'], _: ['user'] },
      resources: { media: ['photo', 'video'], _: ['profile'] },
      actions: ['publish', 'approve']
    });
    ac.grant('user').readOwn('profile', ['*', '!password']);
    ac.grant('admin').readAny('media/photo', ['*']);
    ac.require('$.env == prod');
    ac.category('billing').require('$.ip == trusted');
    ac.resource('billing/invoice').require('$.mfa == true');
    return ac;
  }

  test('getVocabulary() returns unqualified members and round-trips through setup()', () => {
    const ac = buildFull();
    expect(ac.getVocabulary()).toEqual({
      roles: { admins: ['admin', 'moderator'], _: ['user'] },
      resources: { media: ['photo', 'video'], _: ['profile'] },
      actions: ['publish', 'approve']
    });

    // feeding it back into a fresh instance reproduces the same vocabulary
    const ac2 = new AccessControl().setup(ac.getVocabulary());
    expect(ac2.getVocabulary()).toEqual(ac.getVocabulary());
    expect(ac2.getGroups().sort()).toEqual(['admins']);
    expect(ac2.getCategories().sort()).toEqual(['media']);
  });

  test('snapshot() captures grants, requirements and vocabulary as plain JSON', () => {
    const ac = buildFull();
    const snap = ac.snapshot();
    expect(snap.grants).toEqual(ac.getGrants());
    expect(snap.requirements).toEqual(ac.getRequirements());
    expect(snap.vocabulary).toEqual(ac.getVocabulary());
    // detached: survives a JSON round-trip unchanged
    expect(JSON.parse(JSON.stringify(snap))).toEqual(snap);
  });

  test('restore(snapshot()) on a fresh instance reproduces the whole model', () => {
    const ac = buildFull();
    const snap = JSON.parse(JSON.stringify(ac.snapshot())); // through the wire
    const restored = new AccessControl({}, { policy: { ownerField: 'ownerId' } }).restore(snap);

    expect(restored.getGrants()).toEqual(ac.getGrants());
    expect(restored.getRequirements()).toEqual(ac.getRequirements());
    expect(restored.getVocabulary()).toEqual(ac.getVocabulary());

    // and it behaves identically (a gate denies when context fails)
    const ok = { env: 'prod' };
    expect(
      restored.can('user', { ...ok, user: { id: 1 }, profile: { ownerId: 1 } }).readOwn('profile')
        .granted
    ).toBe(true);
    expect(
      restored.can('user', { user: { id: 1 }, profile: { ownerId: 1 } }).readOwn('profile').granted
    ).toBe(false); // global require '$.env == prod' fails
  });

  test('restore() is chainable and returns the instance', () => {
    const ac = new AccessControl();
    expect(ac.restore(buildFull().snapshot())).toBe(ac);
  });

  test('restore() is a full replace: prior state is wiped (instance === snapshot)', () => {
    const ac = buildFull();
    const snap = ac.snapshot();

    // a populated, *different* instance is fully overwritten
    const other = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
    other.grant('ghost').readAny('secret');
    other.require('$.never == true');
    other.setup({ roles: ['stranger'] });

    other.restore(snap);
    expect(other.getGrants()).toEqual(snap.grants); // 'ghost' gone
    expect(other.getRequirements()).toEqual(snap.requirements); // '$.never' gone
    expect(other.getVocabulary()).toEqual(snap.vocabulary); // 'stranger' gone

    // restoring twice is idempotent (no duplicated gates)
    other.restore(snap);
    expect(other.getRequirements()).toEqual(snap.requirements);
  });

  test('restore() of an empty snapshot clears the instance', () => {
    const ac = buildFull();
    ac.restore(new AccessControl().snapshot());
    expect(ac.getGrants()).toEqual({});
    expect(ac.getRequirements()).toEqual({ global: [], categories: {}, resources: {} });
    expect(ac.getVocabulary()).toEqual({ roles: {}, resources: {}, actions: [] });
  });

  test('restore() respects lock()', () => {
    const snap = buildFull().snapshot();
    const ac = new AccessControl();
    ac.grant('user').readAny('post');
    ac.lock();
    expect(() => ac.restore(snap)).toThrow();
  });
});

/** Stable sort key for order-independent list comparison. */
function byRow(a: any, b: any): number {
  return JSON.stringify(a).localeCompare(JSON.stringify(b));
}

describe('during — serialization round-trip', () => {
  const BH = 'T0900:1800 E1:5';
  const monMorning = { now: '2026-07-20T10:00:00Z', tz: 'UTC' };
  const satMorning = { now: '2026-07-18T10:00:00Z', tz: 'UTC' };

  function buildScheduledAc(): AccessControl {
    const ac = new AccessControl();
    ac.grant('editor').where('$.post.status == draft').during(BH).updateAny('post', ['*']);
    ac.require(`$.now during "${BH}"`);
    return ac;
  }

  test('grants + gates with during survive list/object/snapshot round-trips', () => {
    const ac = buildScheduledAc();
    // object → list → object
    const fromList = new AccessControl(ac.getGrantsList());
    expect(fromList.getGrants()).toEqual(ac.getGrants());
    // snapshot → restore (includes the require gates)
    const restored = new AccessControl().restore(ac.snapshot());
    expect(restored.getGrants()).toEqual(ac.getGrants());
    expect(restored.getRequirements()).toEqual(ac.getRequirements());
    expect(restored.getRequirements().global).toEqual([['$.now', 'during', BH]]);
  });

  test('a rebuilt model produces identical check results', () => {
    const ac = buildScheduledAc();
    const restored = new AccessControl().restore(ac.snapshot());
    const draft = { post: { status: 'draft' } };
    for (const when of [monMorning, satMorning]) {
      const ctx = { ...when, ...draft };
      expect(restored.can('editor', ctx).updateAny('post').granted).toBe(
        ac.can('editor', ctx).updateAny('post').granted
      );
    }
    // sanity: the schedule actually flips the verdict across the two contexts
    expect(ac.can('editor', { ...monMorning, ...draft }).updateAny('post').granted).toBe(true);
    expect(ac.can('editor', { ...satMorning, ...draft }).updateAny('post').granted).toBe(false);
  });
});
