import type { Action, Possession } from '../enums/index.js';
import type { ConditionJSON } from './ICondition.js';

/**
 * An interface that defines an access information to be granted or denied.
 * When you start a method chain with `AccessControl#grant` or
 * `AccessControl#deny` methods, you're actually building this  object which
 * will eventually be committed to the underlying grants model.
 */
export interface IAccessInfo {
  /**
   *  Indicates a single or multiple roles for this access information.
   */
  role?: string | string[];
  /**
   *  Indicates a single or multiple target resources for this access
   *  information.
   */
  resource?: string | string[];
  /**
   *  Defines the resource attributes which are granted. If denied, this will
   *  default to an empty array.
   */
  attributes?: string | string[];
  /**
   *  Defines the type of the operation that is (or not) to be performed on the
   *  resource(s) by the defined role(s).
   */
  action?: Action | string;
  /**
   *  Defines the possession of the resource(s) for the specified action. for
   *  possible values.
   */
  possession?: Possession;
  /**
   *  Optional declarative condition attached to this grant.
   */
  condition?: ConditionJSON;
  /**
   *  Flag for denied access.
   *  @private
   */
  denied?: boolean;
}
