/**
 * Separates an action from its possession in the string convention
 * (`create:own`, `read:any`). Also used to re-join them.
 */
export const POSSESSION_SEPARATOR = ':';

/**
 * Separates a group/category from its member (`admins/moderator`,
 * `media/photo`). Reserved for the groups & categories feature.
 */
export const GROUP_SEPARATOR = '/';

/**
 * Reserved key in `setup()`'s `roles`/`resources` objects denoting the
 * **ungrouped / uncategorized** members. Cannot be used as an actual
 * group or category name.
 */
export const GROUP_UNGROUPED = '_';

/**
 * Reserved separators. Excluded from {@link NAME_CHARSET} so they can
 * never appear inside a single name segment.
 */
export const RESERVED_SEPARATORS = [GROUP_SEPARATOR, POSSESSION_SEPARATOR];

/**
 * Inheritance key for the grants model (`{ role: { $extend: [...] } }` in the
 * object form, `{ role, $extend: [...] }` rows in the flat-list form). Prefixed
 * with `$` so that, in the object form where it sits alongside resource names,
 * it can never collide with one (resource names are restricted to
 * {@link NAME_CHARSET}). The `$` also reads consistently with the `$.` notation
 * paths — `$` marks framework-reserved vocabulary. Validation rejects any
 * consumer name containing `$`, so this keyword is reserved by construction.
 */
export const EXTEND_KEY = '$extend';

/**
 * Allowed character set for any consumer-supplied name — roles, resources,
 * actions, groups and categories. Case-preserving; letters, digits,
 * underscore and hyphen only (supports `camelCase` and `kebab-case`). The
 * reserved separators (`/` `:`) and the `$` keyword sigil are excluded by
 * construction.
 */
export const NAME_CHARSET = 'A-Za-z0-9_-';

/**
 * Single source of truth for validating a name segment against
 * {@link NAME_CHARSET}. Anchored, one-or-more, no empty names. This is the only
 * gate for consumer names — it rejects every reserved token (`*` `!` `$`,
 * anything containing `$` such as `$extend`, and the `/` `:` separators).
 */
export const NAME_RE = new RegExp(`^[${NAME_CHARSET}]+$`);

/**
 * Relaxed name pattern for {@link Charset.UNICODE}: Unicode letters/digits plus
 * `_` and `-`. Still excludes the structural characters (`/ : $ * !`) and
 * whitespace by construction. Homograph-prone — see {@link Charset.UNICODE}.
 */
export const NAME_RE_UNICODE = /^[\p{L}\p{N}_-]+$/u;

/**
 * Reserved object-prototype identifiers that match {@link NAME_CHARSET} but must
 * never be accepted as a consumer name (role, resource, action, group or
 * category). These are the classic prototype-pollution gadget keys: using one
 * as an object key either has special JavaScript write semantics (`__proto__`)
 * or shadows an inherited member (`constructor`, `prototype`), which would make
 * a grant silently disappear and/or let a check read an inherited value. They
 * are rejected up front at {@link normalizeName} so they can never reach the
 * internal grants/requirement maps. Comparison is case-sensitive (these exact
 * lowercase spellings are the dangerous ones; `Constructor` is a normal name).
 */
export const RESERVED_NAMES = ['__proto__', 'prototype', 'constructor'];

/**
 * Error message thrown when mutating the grants model after the AccessControl
 * instance has been locked.
 */
export const ERR_LOCK =
  'Cannot alter the underlying grants model. AccessControl instance is locked.';
