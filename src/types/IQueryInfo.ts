import type { Action } from '../enums/Action.js';
import type { Possession } from '../enums/Possession.js';
import type { UnknownObject } from './UnknownObject.js';

/**
 * An interface that defines an access information to be queried.
 * When you start a method chain with `AccessControl#can` method, you're
 * actually building this query object which will be used to check the access
 * permissions.
 */
export interface IQueryInfo {
  /**
   *  Indicates a single or multiple roles to be queried.
   */
  role?: string | string[];
  /**
   *  Indicates the resource to be queried.
   */
  resource?: string;
  /**
   *  Defines the type of the operation that is (or not) to be performed on
   *  the resource by the defined role(s).
   */
  action?: Action | string;
  /**
   *  Defines the possession of the resource for the specified action.
   */
  possession?: Possession;
  /**
   * Per-check context data, readable from conditions via `$.`. Merged
   *  over the constructor's ambient context (per-check wins). Used by the
   *  one-shot `AccessControl#check()` form.
   */
  context?: UnknownObject;
}
