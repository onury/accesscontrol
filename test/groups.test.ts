/**
 *  Test Suite: role groups & resource categories (P6, §7.1).
 *  `/` qualifies group/role and category/resource; group/category grants
 *  cascade dynamically to members; setup() declares vocabulary & feeds strict.
 */

import { AccessControl } from '../src/index.js';
import { helper } from './helper.js';

describe('Test Suite: groups & categories (P6)', () => {
  test('dynamic shared base: a group grant cascades to its members', () => {
    const ac = new AccessControl();
    ac.grant('admins').readAny('post', ['*']); // grant to the GROUP
    // a member of the group inherits at check time, no $extend needed
    expect(ac.can('admins/moderator').readAny('post').granted).toBe(true);
    expect(ac.can('admins/admin').readAny('post').granted).toBe(true);
  });

  test('bounded bulk grant: group × category reaches every member pair', () => {
    const ac = new AccessControl();
    ac.grant('admins').readAny('media', ['*']); // group × category
    expect(ac.can('admins/admin').readAny('media/photo').granted).toBe(true);
    expect(ac.can('admins/moderator').readAny('media/video').granted).toBe(true);
    // outside the category: not covered
    expect(ac.can('admins/admin').readAny('profile').granted).toBe(false);
  });

  test('category grant cascades to a member resource for a plain role', () => {
    const ac = new AccessControl();
    ac.grant('editor').updateAny('media', ['*']);
    expect(ac.can('editor').updateAny('media/photo').granted).toBe(true);
    expect(ac.can('editor').updateAny('media/video').granted).toBe(true);
  });

  test('no collision: media/photo ≠ legal/photo', () => {
    const ac = new AccessControl();
    ac.grant('clerk').readAny('legal/photo', ['*']);
    expect(ac.can('clerk').readAny('legal/photo').granted).toBe(true);
    expect(ac.can('clerk').readAny('media/photo').granted).toBe(false);
  });

  test('a member can carve back via deny-overrides', () => {
    const ac = new AccessControl();
    ac.grant('admins').readAny('post', ['*']); // group grants all
    ac.deny('admins/intern').readAny('post', ['secret']); // member denies a field
    const perm = ac.can('admins/intern').readAny('post');
    expect(perm.granted).toBe(true);
    expect(perm.attributes).not.toContain('secret');
    // a different member keeps the full group grant
    expect(ac.can('admins/admin').readAny('post').attributes).toEqual(['*']);
  });

  test('a specific resource grant unions with its category grant', () => {
    const ac = new AccessControl();
    ac.grant('editor').readAny('media', ['title']); // category-level
    ac.grant('editor').readAny('media/photo', ['caption']); // specific
    expect([...ac.can('editor').readAny('media/photo').attributes].sort()).toEqual([
      'caption',
      'title'
    ]);
  });

  test('setup() declares vocabulary; group()/category() introspect', () => {
    const ac = new AccessControl();
    ac.setup({
      roles: { admins: ['admin', 'moderator'], _: ['user'] },
      resources: { media: ['photo', 'video'], _: ['profile'] },
      actions: ['publish']
    });
    expect(ac.group('admins').getRoles()).toEqual(['admins/admin', 'admins/moderator']);
    expect(ac.category('media').getResources()).toEqual(['media/photo', 'media/video']);
    expect(ac.getGroups()).toEqual(['admins']);
    expect(ac.getCategories()).toEqual(['media']);
  });

  test('setup() accepts a flat array (no groups/categories needed)', () => {
    const ac = new AccessControl({}, { policy: { strict: true } });
    ac.setup({ roles: ['user', 'admin'], resources: ['profile', 'post'] });
    ac.grant('admin').readAny('post', ['*']);
    // declared-but-ungranted flat vocabulary is known under strict (no throw)
    expect(ac.can('user').readAny('profile').granted).toBe(false);
    // no groups/categories were created
    expect(ac.getGroups()).toEqual([]);
    expect(ac.getCategories()).toEqual([]);
    // genuine typo still throws
    helper.expectACError(() => ac.can('ghost').readAny('post').granted);
  });

  test('setup() is chainable & additive', () => {
    const ac = new AccessControl();
    const ret = ac
      .setup({ roles: { admins: ['admin'] } })
      .setup({ roles: { admins: ['moderator'] } }); // additive into same group
    expect(ret).toBe(ac);
    expect(ac.group('admins').getRoles()).toEqual(['admins/admin', 'admins/moderator']);
  });

  test('removeGroup drops the group node so members stop inheriting', () => {
    const ac = new AccessControl();
    ac.setup({ roles: { admins: ['admin'] } });
    ac.grant('admins').readAny('post', ['*']);
    expect(ac.can('admins/admin').readAny('post').granted).toBe(true);
    ac.removeGroup('admins');
    expect(ac.getGroups()).toEqual([]);
    // with strict.roles default and no vocab/grants left, the member is unknown
    helper.expectACError(() => ac.can('admins/admin').readAny('post').granted);
  });

  test('removeCategory drops the category node across roles', () => {
    const ac = new AccessControl();
    ac.grant('editor').readAny('media', ['*']);
    expect(ac.can('editor').readAny('media/photo').granted).toBe(true);
    ac.removeCategory('media');
    expect(ac.can('editor').readAny('media/photo').granted).toBe(false);
  });

  test('strict: declared-but-ungranted vocabulary does not throw; typos do', () => {
    const ac = new AccessControl({}, { policy: { strict: true } });
    ac.setup({
      roles: { admins: ['admin'], _: ['user'] },
      resources: { media: ['photo'], _: ['profile'] },
      actions: ['publish']
    });
    ac.grant('admins').readAny('media', ['*']);
    // declared vocabulary is "known" → granted:false, not a throw
    expect(ac.can('user').readAny('profile').granted).toBe(false);
    expect(ac.can('admins/admin').action('publish', 'media/photo').granted).toBe(false);
    // genuine typos throw under strict
    helper.expectACError(() => ac.can('ghost').readAny('media/photo').granted); // unknown role
    helper.expectACError(() => ac.can('admins/admin').readAny('ghostres').granted); // unknown resource
    helper.expectACError(() => ac.can('admins/admin').action('frob', 'media/photo').granted); // action
  });

  test('introspection of an unknown group/category returns empty; actions-only setup', () => {
    const ac = new AccessControl();
    ac.setup({ actions: ['publish', 'publish'] }); // dedupes; no roles/resources
    expect(ac.group('nope').getRoles()).toEqual([]);
    expect(ac.category('nope').getResources()).toEqual([]);
    expect(ac.getGroups()).toEqual([]);
  });

  test('self-grant and group-grant on the same member are merged', () => {
    const ac = new AccessControl();
    ac.grant('admins').readAny('post', ['title']); // via group
    ac.grant('admins/admin').readAny('post', ['body']); // directly on the member
    expect([...ac.can('admins/admin').readAny('post').attributes].sort()).toEqual([
      'body',
      'title'
    ]);
  });

  test('removeGroup with no group-level grant node is a no-op delete', () => {
    const ac = new AccessControl();
    ac.setup({ roles: { admins: ['admin'] } }); // declared, but never granted
    expect(ac.removeGroup('admins')).toBe(ac);
    expect(ac.getGroups()).toEqual([]);
  });

  test('object-form grants accept qualified role & resource keys', () => {
    const ac = new AccessControl({
      'admins/admin': { 'media/photo': { read: [{ attributes: ['*'] }] } }
    });
    expect(ac.can('admins/admin').readAny('media/photo').granted).toBe(true);
    // category cascade still applies from the qualified resource key
    expect(ac.can('admins/admin').readAny('media').granted).toBe(false);
  });

  test('qualified name validation: single level only, valid segments', () => {
    const ac = new AccessControl();
    helper.expectACError(() => ac.grant('a/b/c').readAny('post')); // nested not allowed
    helper.expectACError(() => ac.grant('admins/').readAny('post')); // empty segment
    helper.expectACError(() => ac.grant('_/admin').readAny('post')); // '_' reserved prefix
    expect(() => ac.grant('admins/admin').readAny('media/photo', ['*'])).not.toThrow();
  });
});

describe('Test Suite: group/category introspection', () => {
  test('hasGroup / hasCategory', () => {
    const ac = new AccessControl();
    ac.setup({ roles: { admins: ['admin'] }, resources: { media: ['photo'] } });
    expect(ac.hasGroup('admins')).toBe(true);
    expect(ac.hasGroup('ghost')).toBe(false);
    expect(ac.hasCategory('media')).toBe(true);
    expect(ac.hasCategory('ghost')).toBe(false);
    // prototype-safe (inherited member names are not "declared")
    expect(ac.hasGroup('toString')).toBe(false);
    expect(ac.hasCategory('toString')).toBe(false);
  });
});
