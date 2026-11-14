// own modules
import { AccessControlError } from '../core/index.js';
import { ErrorCode } from '../enums/index.js';
import type { AccessControl } from '../index.js';
import { deepFreeze, ecode } from './generic.js';

/**
 * Locks the given AccessControl instance by freezing underlying grants
 * model and disabling all functionality to modify it.
 * @param ac
 */
export function lockAC(ac: AccessControl) {
  const _ac = ac as any;
  const code = ecode(_ac._policy.errorCodePrefix, ErrorCode.INVALID_GRANT);
  if (!_ac._grants || Object.keys(_ac._grants).length === 0) {
    throw new AccessControlError('Cannot lock empty or invalid grants model.', { code });
  }

  let locked = ac.isLocked && Object.isFrozen(_ac._grants);
  if (!locked) locked = Boolean(deepFreeze(_ac._grants));

  /* istanbul ignore next */
  if (!locked) {
    throw new AccessControlError(`Could not lock grants: ${typeof _ac._grants}`, { code });
  }

  _ac._isLocked = locked;
}
