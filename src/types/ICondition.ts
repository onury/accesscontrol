/**
 * A comparison leaf: `[lhs, operator, rhs]`. Operands are either notation paths
 * (prefixed by the configured `pathPrefix`, default `$.`) read from the
 * check-time context, or literal values.
 * @example ['$.order.value', '>', 100000]
 * @example ['$.now', 'during', 'T0900:1800 E1:5'] // dtrexp schedule (Mon–Fri, 09:00–18:00)
 */
export type ConditionLeaf = [unknown, string, unknown];

/**
 * A reference to a custom condition function registered via
 * `ac.defineCondition(name, fn)`. Kept JSON-serializable.
 */
export interface ConditionFn {
  fn: string;
  args?: unknown;
}

/**
 * A custom condition function registered via `ac.defineCondition(name, fn)`.
 * Receives the merged check context and the rule's `args`; may be sync
 * or async (evaluated only on the `grantedAsync`/`checkAsync` path).
 */
export type ConditionFunction = (
  context: Record<string, unknown>,
  args?: unknown
) => boolean | Promise<boolean>;

/** A boolean combinator node (`and` / `or` / `not`). */
export interface ConditionCombinator {
  and?: ConditionJSON[];
  or?: ConditionJSON[];
  not?: ConditionJSON;
}

/**
 * A declarative condition attached to a grant. May be:
 * - a comparison **leaf** (`[lhs, op, rhs]`),
 * - a **combinator** object (`{ and | or | not }`),
 * - a **custom-fn** reference (`{ fn, args }`),
 * - or the **string sugar** form (e.g. `'$.order.value > 100000'`, or
 *   `'$.now during "T0900:1800 E1:5"'` for a temporal schedule) which
 *   compiles to the canonical JSON above.
 */
export type ConditionJSON = ConditionLeaf | ConditionCombinator | ConditionFn | string;
