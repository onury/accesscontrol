/**
 * Stable, machine-readable codes attached to every {@link AccessControlError}
 * (`err.code`). Branch on these instead of parsing message strings — messages
 * are redacted by default (`engine.safeErrors`) and may change wording, but
 * codes are part of the public contract.
 *
 */
export enum ErrorCode {
  /** A name (role/resource/action/group/category) is empty or malformed. */
  INVALID_NAME = 'INVALID_NAME',
  /** A name is a reserved prototype-pollution keyword (`__proto__`, …). */
  RESERVED_NAME = 'RESERVED_NAME',
  /** A check query (`IQueryInfo` passed to `can`/`check`) is malformed. */
  INVALID_QUERY = 'INVALID_QUERY',
  /** A grant rule / grants object / `IAccessInfo` has an invalid shape. */
  INVALID_GRANT = 'INVALID_GRANT',
  /** The `setup()` vocabulary object is malformed. */
  INVALID_SETUP = 'INVALID_SETUP',
  /** An action name or possession is invalid. */
  INVALID_ACTION = 'INVALID_ACTION',
  /** A referenced role does not exist. */
  ROLE_NOT_FOUND = 'ROLE_NOT_FOUND',
  /** Inheritance is invalid (self-extend, cross-inheritance, non-existent). */
  INVALID_INHERITANCE = 'INVALID_INHERITANCE',
  /** `strict.actions`: the checked action is not in the known set. */
  UNKNOWN_ACTION = 'UNKNOWN_ACTION',
  /** `strict.resources`: the checked resource is not in the known set. */
  UNKNOWN_RESOURCE = 'UNKNOWN_RESOURCE',
  /** A mutation was attempted after `lock()`. */
  LOCKED = 'LOCKED',
  /** The check needs the async path (a custom/async `{ fn }` condition). */
  ASYNC_REQUIRED = 'ASYNC_REQUIRED',
  /** A condition is malformed, uncompiled, or nested too deep. */
  INVALID_CONDITION = 'INVALID_CONDITION',
  /** A custom condition function name is not registered. */
  UNKNOWN_CONDITION_FN = 'UNKNOWN_CONDITION_FN',
  /** The `matches` operator is disabled (`engine.allowRegex` is off). */
  REGEX_DISABLED = 'REGEX_DISABLED',
  /** A regular expression is malformed or potentially catastrophic. */
  UNSAFE_REGEX = 'UNSAFE_REGEX'
}
