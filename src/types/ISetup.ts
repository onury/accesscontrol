/**
 * Vocabulary declaration for {@link AccessControl#setup}.
 *
 * `setup()` declares the *vocabulary* (which roles/groups, resources/categories
 * and actions exist); `grant()` declares *permissions*. For `roles` and
 * `resources` pass **either** a plain array (when you don't need groups /
 * categories — all members are ungrouped) **or** a map keyed by group / category
 * name, with the reserved `_` key listing the ungrouped / uncategorized members.
 *
 * @example
 * // flat — no groups/categories needed
 * ac.setup({ roles: ['user', 'admin'], resources: ['profile', 'post'] });
 *
 * @example
 * // grouped
 * ac.setup({
 *   roles:     { admins: ['admin', 'moderator'], _: ['user', 'viewer'] },
 *   resources: { media: ['photo', 'video'], _: ['profile'] },
 *   actions:   ['publish', 'approve'],
 * });
 */
export interface ISetup {
  /**
   * Either a flat array of (ungrouped) roles, or a `group → member roles` map.
   * In the map form the reserved `_` key lists ungrouped roles.
   */
  roles?: string[] | Record<string, string[]>;
  /**
   * Either a flat array of (uncategorized) resources, or a `category → member
   * resources` map. In the map form the reserved `_` key lists uncategorized ones.
   */
  resources?: string[] | Record<string, string[]>;
  /** Declared custom actions (feeds `strict.actions`). */
  actions?: string[];
}
