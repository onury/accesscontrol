/**
 *  Enumerates the possible possessions of a resource, for an action.
 *  A possession defines whether the action is (or not) to be performed on "own"
 *  resource(s) of the current subject or "any" resources - including "own".
 *  @enum {String}
 *  @readonly
 *  @memberof! AccessControl
 */
declare const Possession: {
    OWN: string;
    ANY: string;
};
export { Possession };
