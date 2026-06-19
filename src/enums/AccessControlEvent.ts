/**
 * The three observational events emitted by `AccessControl`. Values are
 * the plain strings, so `ac.on('access', …)` and `ac.on(AccessControlEvent.Access,
 * …)` are equivalent.
 */
export enum AccessControlEvent {
  /** Every check resolved (granted **and** denied) — the access audit log. */
  Access = 'access',
  /** The grants model or vocabulary mutated (policy-edit audit). */
  Change = 'change',
  /** A check or operation threw. */
  Error = 'error'
}
