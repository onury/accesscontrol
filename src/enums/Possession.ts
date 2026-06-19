/**
 * Enumerates the possible possessions of a resource, for an action.
 * A possession defines whether the action is (or not) to be performed on "own"
 * resource(s) of the current subject or "any" resources - including "own".
 */
export enum Possession {
  /**
   *  Indicates that the action is (or not) to be performed on <b>own</b>
   *  resource(s) of the current subject.
   */
  OWN = 'own',
  /**
   *  Indicates that the action is (or not) to be performed on <b>any</b>
   *  resource(s); including <i>own</i> resource(s) of the current subject.
   */
  ANY = 'any'
}
