/**
 *  Test Suite: ownership & possession (P4, §5.7).
 *  `own` becomes an engine-enforced check: ownerField convention or owner(ctx)
 *  resolver; strict.checks governs the unverifiable case; `any` ⊇ `own` cascade.
 */

import { AccessControl } from '../src/index.js';

describe('Test Suite: ownership (P4)', () => {
  test('ownerField: granted when the record belongs to the requester', () => {
    const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
    ac.grant('user').updateOwn('order', ['*']);

    // record supplied in context keyed by resource name; user owns it
    expect(
      ac.can('user', { user: { id: 7 }, order: { ownerId: 7 } }).updateOwn('order').granted
    ).toBe(true);
    // someone else's record ⇒ denied
    expect(
      ac.can('user', { user: { id: 7 }, order: { ownerId: 9 } }).updateOwn('order').granted
    ).toBe(false);
  });

  test('strict.checks default (true): no record ⇒ own denied when a resolver is set', () => {
    const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
    ac.grant('user').readOwn('order', ['*']);
    // resolver configured but no record/owner in context ⇒ unverifiable ⇒ deny
    expect(ac.can('user', { user: { id: 7 } }).readOwn('order').granted).toBe(false);
    expect(ac.can('user').readOwn('order').granted).toBe(false);
  });

  test('strict.checks false: unverifiable falls back to v2 (own attribute set)', () => {
    const ac = new AccessControl(
      {},
      { policy: { ownerField: 'ownerId', strict: { checks: false } } }
    );
    ac.grant('user').readOwn('order', ['*', '!secret']);
    const perm = ac.can('user').readOwn('order'); // no record
    expect(perm.granted).toBe(true);
    expect(perm.attributes).toEqual(['*', '!secret']);
  });

  test('no resolver configured ⇒ own is not gated (v2 behavior, option b)', () => {
    const ac = new AccessControl(); // no policy at all
    ac.grant('user').readOwn('account', ['*']);
    expect(ac.can('user').readOwn('account').granted).toBe(true);
  });

  test('custom owner(ctx) resolver wins over ownerField', () => {
    const ac = new AccessControl(
      {},
      {
        policy: {
          ownerField: 'ownerId', // ignored because owner() is set
          owner: (ctx: any) => ctx.user?.id === ctx.order?.creatorId
        }
      }
    );
    ac.grant('user').deleteOwn('order', ['*']);
    expect(
      ac.can('user', { user: { id: 5 }, order: { creatorId: 5 } }).deleteOwn('order').granted
    ).toBe(true);
    expect(
      ac.can('user', { user: { id: 5 }, order: { creatorId: 6 } }).deleteOwn('order').granted
    ).toBe(false);
  });

  test('any ⊇ own cascade: an `any` grant satisfies an own check without ownership', () => {
    const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
    ac.grant('admin').updateAny('order', ['*']);
    // no record supplied, but the blanket `any` grant cascades to `own`
    expect(ac.can('admin').updateOwn('order').granted).toBe(true);
  });

  test('own grant does not satisfy an `any` check', () => {
    const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
    ac.grant('user').updateOwn('order', ['*']);
    expect(
      ac.can('user', { user: { id: 7 }, order: { ownerId: 7 } }).updateAny('order').granted
    ).toBe(false);
  });

  test('ownership stored as possession only (no synthetic condition)', () => {
    const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
    ac.grant('user').updateOwn('order', ['*']);
    const rule = (ac.getGrants() as any).user.order.update[0];
    expect(rule.possession).toBe('own');
    expect(rule.condition).toBeUndefined();
  });

  test('deny own only subtracts when the requester owns the record', () => {
    const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
    ac.grant('user').readAny('order', ['*']); // blanket read
    ac.deny('user').readOwn('order'); // ... but not your own

    // owns it ⇒ deny applies ⇒ subtracted from the `own` view.
    // (the `any` grant still cascades into the own check, so to see the deny we
    // compare the own-scoped resolution.)
    const owns = ac.can('user', { user: { id: 7 }, order: { ownerId: 7 } }).readOwn('order');
    const notOwns = ac.can('user', { user: { id: 7 }, order: { ownerId: 9 } }).readOwn('order');
    // not the owner ⇒ deny:own drops out ⇒ the any grant stands
    expect(notOwns.granted).toBe(true);
    // owner ⇒ deny:own subtracts everything
    expect(owns.granted).toBe(false);
  });
});
