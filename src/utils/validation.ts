// own modules
import { AccessControlError } from '../core/index.js';
import { type Action, ErrorCode, Possession, possessions } from '../enums/index.js';
import type { IAccessInfo, IGrantsListItem, IQueryInfo } from '../types/index.js';
import {
  GROUP_SEPARATOR,
  GROUP_UNGROUPED,
  NAME_RE,
  POSSESSION_SEPARATOR,
  RESERVED_NAMES
} from './constants.js';
import {
  detail,
  ecode,
  hasDefined,
  impliedStar,
  isEmptyArray,
  toStringArray,
  type
} from './generic.js';

// ----------------------
// AC VALIDATION UTILS
// ----------------------

/**
 * Per-instance name/error policy threaded into the validation helpers from the
 * engine. Defaults are secure: ASCII charset, redacted (safe) error messages.
 */
export interface INameOptions {
  /** Allowed-name pattern (`engine.charset`). Defaults to the ASCII set. */
  charset?: RegExp;
  /** `engine.safeErrors` — when `true` (default), messages omit dynamic input. */
  safeErrors?: boolean;
  /** `engine.errorCodePrefix` — prepended to every `err.code` (default `''`). */
  errorCodePrefix?: string;
}

/**
 * Checks whether the given access info can be commited to grants model.
 * @param info
 */
export function isInfoFulfilled(info: IAccessInfo | IQueryInfo): boolean {
  return hasDefined(info, 'role') && hasDefined(info, 'action') && hasDefined(info, 'resource');
}

/**
 * Validates and normalizes a single name (role, resource or action segment).
 * Case-preserving; trims ends; allows the configured charset (ASCII by default).
 * Always rejects the structural separators (`/` `:`), the `$` sigil and the
 * reserved prototype-pollution keywords (`__proto__`, `prototype`,
 * `constructor`).
 *
 * With `allowQualified` (roles/resources) a single `/` is permitted,
 * splitting a `group/role` or `category/resource` name; each side must be a
 * valid segment and the prefix may not be the reserved `_` sentinel.
 *
 * @throws {AccessControlError} - If the name is not a valid string.
 */
export function normalizeName(
  name: unknown,
  allowQualified: boolean = false,
  opts: INameOptions = {}
): string {
  const re = opts.charset ?? NAME_RE;
  const safe = opts.safeErrors !== false;
  if (typeof name !== 'string' || name.trim() === '') {
    throw new AccessControlError(
      `Invalid name, expected a non-empty string.${detail(safe, name)}`,
      {
        code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_NAME)
      }
    );
  }
  const trimmed = name.trim();
  if (allowQualified && trimmed.includes(GROUP_SEPARATOR)) {
    const parts = trimmed.split(GROUP_SEPARATOR);
    if (parts.length !== 2 || !re.test(parts[0]) || !re.test(parts[1])) {
      throw new AccessControlError(
        `Invalid qualified name. Expected "group/name" with valid segments (single level).${detail(safe, name)}`,
        { code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_NAME) }
      );
    }
    if (parts[0] === GROUP_UNGROUPED) {
      throw new AccessControlError(
        `Invalid name. "_" is reserved (ungrouped).${detail(safe, name)}`,
        { code: ecode(opts.errorCodePrefix, ErrorCode.RESERVED_NAME) }
      );
    }
    if (RESERVED_NAMES.includes(parts[0]) || RESERVED_NAMES.includes(parts[1])) {
      throw new AccessControlError(`Invalid name. Reserved keyword.${detail(safe, name)}`, {
        code: ecode(opts.errorCodePrefix, ErrorCode.RESERVED_NAME)
      });
    }
    return trimmed;
  }
  if (!re.test(trimmed)) {
    throw new AccessControlError(
      `Invalid name. Allowed characters: letters, digits, "_" and "-" (see engine.charset).${detail(safe, name)}`,
      { code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_NAME) }
    );
  }
  if (RESERVED_NAMES.includes(trimmed)) {
    throw new AccessControlError(`Invalid name. Reserved keyword.${detail(safe, name)}`, {
      code: ecode(opts.errorCodePrefix, ErrorCode.RESERVED_NAME)
    });
  }
  return trimmed;
}

/**
 * Boolean form of {@link normalizeName} — used to test/skip keys (e.g. to skip
 * `$extend` while iterating a role's resources).
 *
 * @param name - Name to be checked.
 * @param [throwOnInvalid=true] - Whether to throw if the name is not valid.
 * @param [allowQualified=false] - Whether a single `/` group/category qualifier
 * is permitted.
 * @param [opts] - Charset / safe-errors policy.
 * @throws {AccessControlError} - If `throwOnInvalid` and the name is invalid.
 */
export function validName(
  name: string,
  throwOnInvalid: boolean = true,
  allowQualified: boolean = false,
  opts: INameOptions = {}
): boolean {
  try {
    normalizeName(name, allowQualified, opts);
    return true;
  } catch (err) {
    if (!throwOnInvalid) return false;
    throw err;
  }
}

/**
 * Checks whether all of the given name(s) are valid.
 *
 * @param list - Name(s) to be checked.
 * @param [throwOnInvalid=true] - Whether to throw if a name is not valid.
 * @param [allowQualified=false] - Whether a single `/` qualifier is permitted.
 * @param [opts] - Charset / safe-errors policy.
 * @throws {AccessControlError} - If `throwOnInvalid` and a name is invalid.
 */
export function hasValidNames(
  list: string | string[],
  throwOnInvalid: boolean = true,
  allowQualified: boolean = false,
  opts: INameOptions = {}
): boolean {
  return toStringArray(list).every((name: string) =>
    validName(name, throwOnInvalid, allowQualified, opts)
  );
}

/**
 * Normalizes the action (and possession) in the given query/access info.
 * Action may carry possession via the `:own`/`:any` convention (e.g.
 * `'create:own'`) or possession may be a separate property. Possession defaults
 * to `'any'`. Any valid name is a permitted action; the CRUD `Action`
 * constants are just convenience.
 *
 * @throws {AccessControlError} - If invalid action/possession found.
 */
export function normalizeActionPossession(
  info: IQueryInfo | IAccessInfo | Partial<IGrantsListItem>,
  opts: INameOptions = {}
): IQueryInfo | IAccessInfo {
  const safe = opts.safeErrors !== false;
  if (typeof info.action !== 'string' || info.action.trim() === '') {
    throw new AccessControlError(`Invalid action.${detail(safe, info)}`, {
      code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_ACTION)
    });
  }

  const s = info.action.split(POSSESSION_SEPARATOR);
  // any valid name is a permitted action (not just CRUD). The `Action` enum
  // stays as CRUD convenience constants; unknown-action protection is opt-in via
  // `strict.actions`, enforced at check time.
  const action = normalizeName(s[0], false, opts);
  info.action = action as Action;

  const poss = (info as IAccessInfo).possession ?? s[1];
  if (poss !== undefined && poss !== null && String(poss).trim() !== '') {
    const p = String(poss).trim();
    if (possessions.indexOf(p) < 0) {
      throw new AccessControlError(`Invalid action possession.${detail(safe, poss)}`, {
        code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_ACTION)
      });
    }
    (info as IAccessInfo).possession = p as Possession;
  } else {
    // if no possession is set, default to "any".
    (info as IAccessInfo).possession = Possession.ANY;
  }

  return info as IQueryInfo | IAccessInfo;
}

/**
 * Normalizes the roles, resource and action in the given `IQueryInfo`.
 * @throws {AccessControlError} - If invalid role/resource/action found.
 */
export function normalizeQueryInfo(query: IQueryInfo, opts: INameOptions = {}): IQueryInfo {
  const safe = opts.safeErrors !== false;
  if (type(query) !== 'object') {
    throw new AccessControlError(`Invalid IQueryInfo.${detail(safe, typeof query)}`, {
      code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_QUERY)
    });
  }
  query = Object.assign({}, query);

  const roles = toStringArray(query.role);
  if (roles.length === 0) {
    throw new AccessControlError(`Invalid role(s).${detail(safe, query.role)}`, {
      code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_NAME)
    });
  }
  query.role = roles.map((r: string) => normalizeName(r, true, opts));

  if (typeof query.resource !== 'string' || query.resource.trim() === '') {
    throw new AccessControlError(`Invalid resource.${detail(safe, query.resource)}`, {
      code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_NAME)
    });
  }
  query.resource = normalizeName(query.resource, true, opts);

  query = normalizeActionPossession(query, opts) as IQueryInfo;
  return query;
}

/**
 * Normalizes the roles, resources and attributes in the given `IAccessInfo`.
 * Attributes default to `['*']` when omitted (a deny rule with omitted
 * attributes therefore denies **all** attributes; deny-overrides).
 *
 * @param access
 * @param [all=false] - Whether to also validate/normalize `action`/`possession`.
 * @param [opts] - Charset / safe-errors policy.
 * @throws {AccessControlError} - If invalid role/resource found.
 */
export function normalizeAccessInfo(
  access: IAccessInfo | IGrantsListItem,
  all: boolean = false,
  opts: INameOptions = {}
): IAccessInfo {
  const safe = opts.safeErrors !== false;
  if (type(access) !== 'object') {
    throw new AccessControlError(`Invalid IAccessInfo.${detail(safe, typeof access)}`, {
      code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_GRANT)
    });
  }
  const accessInfo = Object.assign({}, access) as IAccessInfo & { effect?: string };

  // a deny may be expressed via `denied` (builder) or `effect: 'deny'` (list row)
  if (accessInfo.effect === 'deny') accessInfo.denied = true;

  const roles = toStringArray(accessInfo.role);
  if (roles.length === 0) {
    throw new AccessControlError(`Invalid role(s).${detail(safe, accessInfo.role)}`, {
      code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_NAME)
    });
  }
  accessInfo.role = roles.map((r: string) => normalizeName(r, true, opts));

  const resources = toStringArray(accessInfo.resource);
  if (resources.length === 0) {
    throw new AccessControlError(`Invalid resource(s).${detail(safe, accessInfo.resource)}`, {
      code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_NAME)
    });
  }
  accessInfo.resource = resources.map((r: string) => normalizeName(r, true, opts));

  // omitted ⇒ all attributes; explicit `[]` is preserved (grant/deny nothing);
  // a negation-only list implies a leading '*' (e.g. ['!password'] ⇒ ['*','!password'])
  accessInfo.attributes =
    accessInfo.attributes === undefined || accessInfo.attributes === null
      ? ['*']
      : impliedStar(toStringArray(accessInfo.attributes));

  if (all) normalizeActionPossession(accessInfo, opts);

  return accessInfo;
}

/**
 * Used to re-set (prepare) the `attributes` of an `IAccessInfo` object when it
 * is first initialized via the `.grant()` / `.deny()` chain. Omitted/empty
 * attributes default to `['*']`.
 * @param access
 */
export function resetAttributes(access: IAccessInfo): IAccessInfo {
  if (!access.attributes || isEmptyArray(access.attributes)) {
    access.attributes = ['*'];
  }
  return access;
}
