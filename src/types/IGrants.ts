import type { ConditionJSON } from './ICondition.js';

/**
 * A single grant rule for an action on a resource (the v3 `Grant`).
 *
 * Multiple rules may exist per action (e.g. different conditions / attributes),
 * so a resource's action maps to an **array** of these.
 */
export interface IGrant {
  /** Allowed attributes in glob notation, e.g. `['*', '!password']`. */
  attributes: string[];
  /**
   * Ownership scope. Omitted ⇒ `'any'` (no ownership gate). `'own'` is
   * enforced via the configured ownership resolver at check time.
   */
  possession?: 'own' | 'any';
  /**
   * Optional declarative condition (JSON tree or `{ fn, args }`) evaluated
   * against the check-time context. Omitted ⇒ unconditional.
   */
  condition?: ConditionJSON;
  /**
   * `'grant'` (default) adds access; `'deny'` subtracts it (deny-overrides).
   */
  effect?: 'grant' | 'deny';
}

/** Maps an action name (e.g. `'create'`, `'publish'`) to its grant rules. */
export interface IResourceGrants {
  [action: string]: IGrant[];
}

/**
 * A role's grants: a map of resource name → its action rules, plus an optional
 * `$extend` array listing inherited roles.
 */
export interface IGrantsItem {
  /** Inherited role(s). */
  $extend?: string[];
  /** Resource name → action rules. */
  [resource: string]: IResourceGrants | string[] | undefined;
}

/**
 * The grants object passed to / returned by AccessControl. Maps roles to their
 * granted permissions.
 *
 * @example
 * const grants: IGrants = {
 *   admin: {
 *     $extend: ['editor'],
 *     video: { delete: [{ possession: 'any', attributes: ['*'] }] }
 *   },
 *   editor: {
 *     video: { read: [{ possession: 'any', attributes: ['*'] }] }
 *   }
 * };
 */
export interface IGrants {
  [role: string]: IGrantsItem;
}

/**
 * A flat grants list item — the DB-friendly form. Either a **rule** row
 * (`role` + `resource` + `action` …) or an **inheritance** row
 * (`role` + `$extend`). See {@link IGrantsList}.
 */
export interface IGrantsListItem {
  /** The role this row belongs to. */
  role: string;
  /** Target resource (omit for an inheritance row). */
  resource?: string;
  /**
   * Action, optionally with possession via the `:own`/`:any` convention
   * (e.g. `'create'` or `'create:own'`). Omit for an inheritance row.
   */
  action?: string;
  /** Ownership scope (alternative to the `:own`/`:any` suffix on `action`). */
  possession?: 'own' | 'any';
  /** Granted attributes — comma/semicolon string or string array. */
  attributes?: string | string[];
  /** Optional declarative condition. */
  condition?: ConditionJSON;
  /** `'grant'` (default) or `'deny'`. */
  effect?: 'grant' | 'deny';
  /** Inherited role(s) — present only on an inheritance row. */
  $extend?: string | string[];
}

/** Grants list to be passed to AccessControl's constructor. */
export type IGrantsList = IGrantsListItem[];
