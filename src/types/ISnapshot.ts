import type { IRequirements } from './IAccessControlOptions.js';
import type { IGrants } from './IGrants.js';
import type { ISetup } from './ISetup.js';

/**
 * A complete, serializable picture of an {@link AccessControl} instance —
 * everything needed to reconstruct it. Produced by
 * {@link AccessControl#snapshot} and consumed by {@link AccessControl#restore}.
 *
 * It bundles the three structures that otherwise persist separately:
 * - **grants** — the role → resource → action rules (incl. conditions & `$extend`).
 * - **requirements** — the `require()` gates, by scope.
 * - **vocabulary** — the `setup()` input (groups, categories, custom actions).
 *
 * All three are plain JSON, so a snapshot round-trips through `JSON.stringify`
 * / a `JSONB` column and back:
 *
 * @example
 * const snap = ac.snapshot();
 * await db.savePolicy(JSON.stringify(snap));
 * // …later, on boot:
 * const ac2 = new AccessControl().restore(await db.loadPolicy());
 */
export interface ISnapshot {
  /** Grant rules in object form (the {@link AccessControl#getGrants} shape). */
  grants: IGrants;
  /** `require()` gates by scope (the {@link AccessControl#getRequirements} shape). */
  requirements: IRequirements;
  /** `setup()` vocabulary — groups, categories and custom actions. */
  vocabulary: ISetup;
}
