// own modules
import { AccessControlError } from '../core/index.js';
import { ErrorCode } from '../enums/index.js';
import type { IGrants } from '../types/index.js';
import { detail, each, ecode, isEmptyArray, toStringArray, uniqConcat } from './generic.js';
import { type INameOptions, normalizeName } from './validation.js';

// ----------------------
// AC ROLE UTILS
// ----------------------

/**
 * Gets a flat, ordered list of inherited roles for the given role.
 * @param grants - Main grants object to be processed.
 * @param roleName - Role name to be inspected.
 * @param [opts] - Charset / safe-errors policy.
 */
export function getRoleHierarchyOf(
  grants: IGrants,
  roleName: string,
  opts: INameOptions = {},
  _rootRole?: string
): string[] {
  // `_rootRole` is for memory storage. Do NOT set it when using;
  // and do NOT document this parameter.
  const safe = opts.safeErrors !== false;

  // Object.hasOwn (not a truthy read) so a name matching an inherited member
  // (`toString`, `valueOf`, …) is correctly "not found" and never reads/mutates
  // a shared builtin.
  if (!Object.hasOwn(grants, roleName)) {
    throw new AccessControlError(`Role not found.${detail(safe, roleName)}`, {
      code: ecode(opts.errorCodePrefix, ErrorCode.ROLE_NOT_FOUND),
      role: roleName
    });
  }
  const role = grants[roleName];

  let arr = [roleName];
  if (!Array.isArray(role.$extend) || role.$extend.length === 0) return arr;

  role.$extend.forEach((exRoleName: string) => {
    if (!Object.hasOwn(grants, exRoleName)) {
      throw new AccessControlError(`Role not found.${detail(safe, exRoleName)}`, {
        code: ecode(opts.errorCodePrefix, ErrorCode.ROLE_NOT_FOUND),
        role: exRoleName
      });
    }
    if (exRoleName === roleName) {
      throw new AccessControlError(`Cannot extend a role by itself.${detail(safe, roleName)}`, {
        code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_INHERITANCE),
        role: roleName
      });
    }
    // throw if cross-inheritance and also avoid memory leak with
    // maximum call stack error
    if (_rootRole && _rootRole === exRoleName) {
      throw new AccessControlError(`Cross inheritance is not allowed.${detail(safe, exRoleName)}`, {
        code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_INHERITANCE),
        role: exRoleName
      });
    }
    const ext = getRoleHierarchyOf(grants, exRoleName, opts, _rootRole || roleName);
    arr = uniqConcat(arr, ext);
  });
  return arr;
}

/**
 * Checks the given grants model and gets an array of non-existent roles
 * from the given roles.
 * @param grants - Grants model to be checked.
 * @param roles - Roles to be checked.
 */
export function getNonExistentRoles(grants: IGrants, roles: string[]): string[] {
  const non: string[] = [];
  if (isEmptyArray(roles)) return non;
  for (const role of roles) {
    if (!Object.hasOwn(grants, role)) non.push(role);
  }
  return non;
}

/**
 * Checks whether the given extender role(s) is already (cross) inherited
 * by the given role and returns the first cross-inherited role. Otherwise,
 * returns `null`.
 *
 * Note that cross-inheritance is not allowed.
 *
 * @param grants - Grants model to be checked.
 * @param roleName - Target role to be checked.
 * @param extenderRoles - Extender role(s) to be checked.
 * @param [opts] - Charset / safe-errors policy.
 */
export function getCrossExtendingRole(
  grants: IGrants,
  roleName: string,
  extenderRoles: string | string[],
  opts: INameOptions = {}
): string | null {
  const extenders = toStringArray(extenderRoles);
  let crossInherited: null | string = null;
  each(extenders, (e: string) => {
    if (crossInherited || roleName === e) {
      return false; // break out of loop
    }

    const inheritedByExtender = getRoleHierarchyOf(grants, e, opts);
    each(inheritedByExtender, (r: string) => {
      if (r === roleName) {
        // get/report the parent role
        crossInherited = e;
        return false; // break out of loop
      }
      return true; // continue
    });

    return true; // continue
  });

  return crossInherited;
}

/**
 * Extends the given role(s) with privileges of one or more other roles.
 *
 * @param grants
 * @param roles - Role(s) to be extended. If a role does not exist, it will be
 * automatically created.
 * @param extenderRoles - Role(s) to inherit from. If an extender role does not
 * exist, it will throw.
 * @param [opts] - Charset / safe-errors policy.
 *
 * @throws {AccessControlError} - If a role is extended by itself, a non-existent
 * role or a cross-inherited role.
 */
export function extendRole(
  grants: IGrants,
  roles: string | string[],
  extenderRoles: string | string[],
  opts: INameOptions = {}
): void {
  const safe = opts.safeErrors !== false;
  const arrRoles = toStringArray(roles).map((r: string) => normalizeName(r, true, opts));
  if (arrRoles.length === 0) {
    throw new AccessControlError(`Invalid role(s).${detail(safe, roles)}`, {
      code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_NAME)
    });
  }

  // extenderRoles cannot be omitted but can be an empty array
  if (isEmptyArray(extenderRoles)) return;

  const arrExtRoles = toStringArray(extenderRoles).map((r: string) => normalizeName(r, true, opts));
  if (arrExtRoles.length === 0) {
    throw new AccessControlError(`Cannot inherit invalid role(s).${detail(safe, extenderRoles)}`, {
      code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_INHERITANCE)
    });
  }

  const nonExistentExtRoles = getNonExistentRoles(grants, arrExtRoles);
  if (nonExistentExtRoles.length > 0) {
    throw new AccessControlError(
      `Cannot inherit non-existent role(s).${detail(safe, nonExistentExtRoles.join(', '))}`,
      {
        code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_INHERITANCE),
        role: nonExistentExtRoles
      }
    );
  }

  arrRoles.forEach((roleName: string) => {
    if (!Object.hasOwn(grants, roleName)) {
      throw new AccessControlError(`Role not found.${detail(safe, roleName)}`, {
        code: ecode(opts.errorCodePrefix, ErrorCode.ROLE_NOT_FOUND),
        role: roleName
      });
    }

    if (arrExtRoles.indexOf(roleName) >= 0) {
      throw new AccessControlError(`Cannot extend a role by itself.${detail(safe, roleName)}`, {
        code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_INHERITANCE),
        role: roleName
      });
    }

    const crossInherited = getCrossExtendingRole(grants, roleName, arrExtRoles, opts);
    if (crossInherited) {
      throw new AccessControlError(
        `Cross inheritance is not allowed.${detail(safe, crossInherited)}`,
        {
          code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_INHERITANCE),
          role: crossInherited
        }
      );
    }

    const r = grants[roleName];
    if (Array.isArray(r.$extend)) {
      r.$extend = uniqConcat(r.$extend, arrExtRoles);
    } else {
      r.$extend = arrExtRoles;
    }
  });
}

/**
 * Pre-creates the role(s) with an empty object, in case the grant chain is not
 * terminated by an action method (e.g. just `ac.grant('user')`).
 * @param grants
 * @param roles
 * @param [opts] - Charset / safe-errors policy.
 */
export function preCreateRoles(
  grants: IGrants,
  roles: string | string[],
  opts: INameOptions = {}
): void {
  const safe = opts.safeErrors !== false;
  const arrRoles = toStringArray(roles).map((r: string) => normalizeName(r, true, opts));
  if (arrRoles.length === 0) {
    throw new AccessControlError(`Invalid role(s).${detail(safe, roles)}`, {
      code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_NAME)
    });
  }
  arrRoles.forEach((role: string) => {
    if (!Object.hasOwn(grants, role)) grants[role] = {};
  });
}
