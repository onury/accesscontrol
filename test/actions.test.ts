/**
 *  Test Suite: custom (non-CRUD) actions & strict mode (P5, §6/§6b).
 */

import { AccessControl } from '../src/index.js';
import { helper } from './helper.js';

describe('Test Suite: custom actions (.action / .do)', () => {
  test('grant & check a custom action', () => {
    const ac = new AccessControl();
    ac.grant('editor').action('publish', 'article', ['*']);
    expect(ac.can('editor').action('publish', 'article').granted).toBe(true);
    expect(ac.can('editor').action('approve', 'article').granted).toBe(false); // ungranted
    // stored under the bare action key, possession defaults to 'any'
    const rule = (ac.getGrants() as any).editor.article.publish[0];
    expect(rule.possession).toBe('any');
  });

  test('.do() is the sanctioned alias — CRUD and custom', () => {
    const ac = new AccessControl();
    ac.grant('admin').do('update', 'post', ['*']);
    ac.grant('admin').do('publish', 'post', ['*']);
    expect(ac.can('admin').do('update', 'post').granted).toBe(true);
    expect(ac.can('admin').do('publish', 'post').granted).toBe(true);
    // do('update') ≡ updateAny
    expect(ac.can('admin').do('update', 'post').granted).toBe(
      ac.can('admin').updateAny('post').granted
    );
  });

  test('custom action with possession is ownership-gated like CRUD', () => {
    const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
    ac.grant('author').action('publish:own', 'article', ['*']);
    expect(
      ac
        .can('author', { user: { id: 1 }, article: { ownerId: 1 } })
        .action('publish:own', 'article').granted
    ).toBe(true);
    expect(
      ac
        .can('author', { user: { id: 1 }, article: { ownerId: 2 } })
        .action('publish:own', 'article').granted
    ).toBe(false);
  });

  test('§5.6 rules carry over: any⊇own, deny, and .where()', () => {
    const ac = new AccessControl();
    // publish:any satisfies a publish:own query (cascade)
    ac.grant('editor').action('publish:any', 'article', ['*']);
    expect(ac.can('editor').action('publish:own', 'article').granted).toBe(true);

    // deny publish:any leaves publish:own (no cross-possession cascade for deny)
    const ac2 = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
    ac2.grant('mod').action('publish:any', 'article', ['*']);
    ac2.grant('mod').action('publish:own', 'article', ['*']);
    ac2.deny('mod').action('publish:any', 'article');
    expect(
      ac2.can('mod', { user: { id: 1 }, article: { ownerId: 1 } }).action('publish:own', 'article')
        .granted
    ).toBe(true);

    // .where() works on a custom action
    const ac3 = new AccessControl();
    ac3.grant('editor').where('$.article.status == draft').action('publish', 'article', ['*']);
    expect(
      ac3.can('editor', { article: { status: 'draft' } }).action('publish', 'article').granted
    ).toBe(true);
    expect(
      ac3.can('editor', { article: { status: 'live' } }).action('publish', 'article').granted
    ).toBe(false);
  });
});

describe('Test Suite: strict mode (§6b)', () => {
  test('strict.actions: unknown action throws; known/CRUD/allow-listed pass', () => {
    const ac = new AccessControl({}, { policy: { strict: { actions: true } } });
    ac.grant('editor').action('publish', 'article', ['*']);
    // known (present in grants) and CRUD are fine
    expect(ac.can('editor').action('publish', 'article').granted).toBe(true);
    expect(ac.can('editor').readAny('article').granted).toBe(false); // CRUD known, just ungranted
    // unknown action throws instead of granted:false
    helper.expectACError(() => ac.can('editor').action('approve', 'article').granted);

    // explicit policy.actions allow-list widens the known set
    const ac2 = new AccessControl(
      {},
      { policy: { strict: { actions: true }, actions: ['approve'] } }
    );
    ac2.grant('editor').action('publish', 'article', ['*']);
    expect(ac2.can('editor').action('approve', 'article').granted).toBe(false); // known, not granted
  });

  test('strict.resources: unknown resource throws', () => {
    const ac = new AccessControl({}, { policy: { strict: { resources: true } } });
    ac.grant('editor').readAny('article', ['*']);
    expect(ac.can('editor').readAny('article').granted).toBe(true);
    helper.expectACError(() => ac.can('editor').readAny('ghost').granted);
  });

  test('strict.roles: default throws on unknown role; false ⇒ lenient', () => {
    const strictAc = new AccessControl();
    strictAc.grant('admin').readAny('post', ['*']);
    helper.expectACError(() => strictAc.can('ghost').readAny('post').granted); // default true

    const lenientAc = new AccessControl({}, { policy: { strict: { roles: false } } });
    lenientAc.grant('admin').readAny('post', ['*']);
    expect(lenientAc.can('ghost').readAny('post').granted).toBe(false); // no throw
  });

  test('strict: true turns everything on; strict: false all lenient', () => {
    const allOn = new AccessControl({}, { policy: { strict: true } });
    allOn.grant('admin').readAny('post', ['*']);
    helper.expectACError(() => allOn.can('admin').action('frobnicate', 'post').granted); // unknown action
    helper.expectACError(() => allOn.can('admin').readAny('ghostres').granted); // unknown resource

    const allOff = new AccessControl({}, { policy: { strict: false } });
    allOff.grant('admin').readAny('post', ['*']);
    expect(allOff.can('ghost').action('frobnicate', 'whatever').granted).toBe(false); // no throws
  });
});
