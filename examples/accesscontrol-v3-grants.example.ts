// ============================================================================
// AccessControl v3 — example grants (constructor input + DB round-trip)
// Domain: a small CMS.  Roles: admin, editor, moderator, author, user.
//         Resources: post, comment, media, profile.
// ============================================================================
//
// WHERE DOES EACH v3 CONCEPT LIVE?
//   - conditions:   INSIDE each grant rule (the `condition` field).      [§A, §B]
//   - groups/cats:  as `/`-qualified NAMES in grants ('staff/editor',
//                   'content/post'); a bare group name ('staff') = a group-level
//                   grant. Membership is declared in setup(). NOT a grant field. [§E]
//   - requirements: a SEPARATE collection of require() gates — NOT in grants.   [§D]
//
import { AccessControl, type IGrants, type IGrantsList } from 'accesscontrol';

// ----------------------------------------------------------------------------
// §A) grantsObject — the CANONICAL, readable form (nested, includes $extend).
//    Grant shape (§5.0):  grants[role][resource][action] = IGrant[]
//      IGrant = { attributes; possession?: 'own'|'any'; condition?; effect? }
//    - possession omitted  => 'any'
//    - effect omitted      => 'grant' ('deny' subtracts; deny-overrides, §5.6)
// ----------------------------------------------------------------------------
export const grantsObject: IGrants = {
  user: {
    post:    { read:   [{ possession: 'any', attributes: ['*', '!authorId'] }] },
    comment: {
      read:   [{ possession: 'any', attributes: ['*'] }],
      // conditional grant: only comment on an unlocked post
      create: [{ possession: 'own', attributes: ['*'],
                 condition: ['$.post.locked', '==', false] }],
    },
    profile: {
      read:   [{ possession: 'own', attributes: ['*'] }],
      update: [{ possession: 'own', attributes: ['email', 'bio'] }],
    },
  },

  author: {
    $extend: ['user'],
    post: {
      create:  [{ possession: 'own', attributes: ['*', '!authorId', '!status'] }],
      update:  [{ possession: 'own', attributes: ['title', 'body'] }],
      // custom action + condition: publish only your OWN drafts
      publish: [{ possession: 'own', attributes: ['*'],
                  condition: ['$.post.status', '==', 'draft'] }],
    },
  },

  moderator: {
    $extend: ['author'],
    comment: { delete: [{ possession: 'any', attributes: ['*'] }] },
    post: {
      update:  [{ possession: 'any', attributes: ['*', '!authorId'] }],
      // DENY-OVERRIDES: moderator inherits author's publish grant, but is
      // explicitly denied it (moderators moderate; they don't publish). (§5.6)
      publish: [{ possession: 'own', attributes: ['*'], effect: 'deny' }],
    },
  },

  editor: {
    $extend: ['author'],
    post:    {
      update: [{ possession: 'any', attributes: ['*', '!authorId'] }],
      delete: [{ possession: 'any', attributes: ['*'] }],
    },
    comment: { delete: [{ possession: 'any', attributes: ['*'] }] },
    media:   { create: [{ possession: 'any', attributes: ['*'] }] },
  },

  admin: {
    $extend: ['editor'],
    media:   { delete: [{ possession: 'any', attributes: ['*'] }] },
    profile: { read:   [{ possession: 'any', attributes: ['*'] }] },
  },
};

// ----------------------------------------------------------------------------
// §B) grantsList — the FLAT, DB-friendly form (1 row <-> 1 ac_grants row).
//    Inheritance travels as `extend` rows (the §3 fix).
//    This is the EXACT equivalent of grantsObject above (1:1, full set).
// ----------------------------------------------------------------------------
export const grantsList: IGrantsList = [
  // --- inheritance ($extend) -> ac_role_inheritance ---
  { role: 'author',    extend: ['user'] },
  { role: 'moderator', extend: ['author'] },
  { role: 'editor',    extend: ['author'] },
  { role: 'admin',     extend: ['editor'] },

  // --- user ---
  { role: 'user', resource: 'post',    action: 'read',   possession: 'any', attributes: ['*', '!authorId'] },
  { role: 'user', resource: 'comment', action: 'read',   possession: 'any', attributes: ['*'] },
  { role: 'user', resource: 'comment', action: 'create', possession: 'own', attributes: ['*'],
    condition: ['$.post.locked', '==', false] },
  { role: 'user', resource: 'profile', action: 'read',   possession: 'own', attributes: ['*'] },
  { role: 'user', resource: 'profile', action: 'update', possession: 'own', attributes: ['email', 'bio'] },

  // --- author (extends user) ---
  { role: 'author', resource: 'post', action: 'create',  possession: 'own', attributes: ['*', '!authorId', '!status'] },
  { role: 'author', resource: 'post', action: 'update',  possession: 'own', attributes: ['title', 'body'] },
  { role: 'author', resource: 'post', action: 'publish', possession: 'own', attributes: ['*'],
    condition: ['$.post.status', '==', 'draft'] },

  // --- moderator (extends author) ---
  { role: 'moderator', resource: 'comment', action: 'delete',  possession: 'any', attributes: ['*'] },
  { role: 'moderator', resource: 'post',    action: 'update',  possession: 'any', attributes: ['*', '!authorId'] },
  { role: 'moderator', resource: 'post',    action: 'publish', possession: 'own', attributes: ['*'], effect: 'deny' },

  // --- editor (extends author) ---
  { role: 'editor', resource: 'post',    action: 'update', possession: 'any', attributes: ['*', '!authorId'] },
  { role: 'editor', resource: 'post',    action: 'delete', possession: 'any', attributes: ['*'] },
  { role: 'editor', resource: 'comment', action: 'delete', possession: 'any', attributes: ['*'] },
  { role: 'editor', resource: 'media',   action: 'create', possession: 'any', attributes: ['*'] },

  // --- admin (extends editor) ---
  { role: 'admin', resource: 'media',   action: 'delete', possession: 'any', attributes: ['*'] },
  { role: 'admin', resource: 'profile', action: 'read',   possession: 'any', attributes: ['*'] },
];

// ----------------------------------------------------------------------------
// §C) Construct from EITHER form (both supported).
// ----------------------------------------------------------------------------
const ac = new AccessControl(grantsObject, {
  policy: { ownerField: 'authorId', strict: { checks: true } },
  // context: { region: 'eu', tz: 'Europe/Istanbul' },
});
// const ac = new AccessControl(grantsList);   // <- identical result

// ----------------------------------------------------------------------------
// §D) Requirements (require() gates, §7.2) — a SEPARATE collection, NOT in the
//     grants object/list. Mandatory; can only restrict. Stored in ac_requirements.
// ----------------------------------------------------------------------------
ac.resource('profile').require('$.ip in [10.0.0.0/8]');                 // internal network only
ac.resource('media').require('$.now.weekday in [mon,tue,wed,thu,fri]'); // weekdays only

// ----------------------------------------------------------------------------
// §E) Groups & categories — declared via setup() (vocabulary), referenced in
//     grants as `/`-qualified names. Membership -> ac_roles.group / ac_resources.category.
// ----------------------------------------------------------------------------
const grouped = new AccessControl();
grouped.setup({
  // group 'staff' has members admin+editor (=> 'staff/admin','staff/editor'); user ungrouped
  roles:     { staff: ['admin', 'editor'], _: ['user'] },
  // category 'content' has post+comment (=> 'content/post','content/comment'); media ungrouped
  resources: { content: ['post', 'comment'], _: ['media'] },
});

// grouped grantsObject: note the `/`-qualified names — THAT is where grouping shows up
export const groupedGrants: IGrants = {
  // bare group name 'staff' => GROUP-LEVEL grant; every staff member inherits it (dynamic base)
  staff: {
    'content/post': { read: [{ possession: 'any', attributes: ['*'] }] },
  },
  // member-specific grant: qualified 'group/role'
  'staff/editor': {
    'content/post': { delete: [{ possession: 'any', attributes: ['*'] }] },
  },
  user: {
    'content/comment': { create: [{ possession: 'own', attributes: ['*'] }] },
  },
};

// same thing, flat:
export const groupedList: IGrantsList = [
  { role: 'staff',        resource: 'content/post',    action: 'read',   possession: 'any', attributes: ['*'] },
  { role: 'staff/editor', resource: 'content/post',    action: 'delete', possession: 'any', attributes: ['*'] },
  { role: 'user',         resource: 'content/comment', action: 'create', possession: 'own', attributes: ['*'] },
];

// bounded bulk grant (the safe '*'): grant to the whole group/category at once
grouped.grant('staff').readAny('content');

// ----------------------------------------------------------------------------
// §F) Use it.
// ----------------------------------------------------------------------------
const post = { id: 1, authorId: 42, status: 'draft', locked: false };
const user = { id: 42 };

ac.can('author', { user, post }).action('publish:own', 'post').granted; // true (own draft)
ac.can('author').do('publish', 'post').granted;                         // .do() alias
ac.can('moderator', { user, post }).publish('post').granted;            // false (denied)

// ----------------------------------------------------------------------------
// §G) Serialize back to the DB.
// ----------------------------------------------------------------------------
const asObject = ac.getGrants();          // nested object -> one JSONB column
const asRows   = ac.getGrantsList();      // flat rows     -> ac_grants (+ extend rows)
const gates    = ac.getRequirements();    // gates         -> ac_requirements
// JSON.stringify(asObject) is safe (custom-fn conditions are stored as { fn, args }).
