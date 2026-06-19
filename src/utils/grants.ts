// dep modules
import { NotationGlob } from 'notation';
// own modules
import { AccessControlError } from '../core/index.js';
import { actions, ErrorCode, possessions } from '../enums/index.js';
import type {
  AccessReason,
  ConditionJSON,
  IAccessInfo,
  IGrant,
  IGrants,
  IGrantsItem,
  IGrantsList,
  IGrantsListItem,
  IQueryInfo,
  IResolveOptions,
  IResourceGrants,
  UnknownObject
} from '../types/index.js';
import { compileCondition, evaluateCondition, evaluateConditionAsync } from './condition.js';
import { EXTEND_KEY, GROUP_SEPARATOR } from './constants.js';
import {
  detail,
  eachKey,
  ecode,
  impliedStar,
  isEmptyArray,
  isFilledStringArray,
  toStringArray,
  type
} from './generic.js';
import { extendRole, getRoleHierarchyOf } from './roles.js';
import {
  type INameOptions,
  normalizeAccessInfo,
  normalizeName,
  normalizeQueryInfo,
  validName
} from './validation.js';

// ----------------------
// AC GRANTS UTILS
// ----------------------

export function eachRole(grants: IGrants, callback: (role: IGrantsItem, roleName: string) => void) {
  eachKey(grants, (name: string) => callback(grants[name], name));
}

export function eachRoleResource(
  grants: IGrants,
  callback: (role: string, resource: string, resourceInfo: IResourceGrants) => void
) {
  eachKey(grants, (role: string) => {
    const roleInfo = grants[role];
    eachKey(roleInfo, (resource: string) => {
      if (validName(resource, false, true)) {
        callback(role, resource, roleInfo[resource] as IResourceGrants);
      }
    });
  });
}

/**
 * Validates and normalizes a single grant rule (`IGrant`). Any `condition` is
 * compiled to canonical JSON (and validated) using the given path prefix.
 */
function normalizeGrant(
  raw: unknown,
  action: string,
  pathPrefix: string,
  opts: INameOptions
): IGrant {
  const safe = opts.safeErrors !== false;
  if (type(raw) !== 'object') {
    throw new AccessControlError(`Invalid grant rule.${detail(safe, action)}`, {
      code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_GRANT),
      action
    });
  }
  const r = raw as Partial<IGrant>;
  const rawAttrs =
    r.attributes === undefined || r.attributes === null ? ['*'] : toStringArray(r.attributes);
  if (!isEmptyArray(rawAttrs) && !isFilledStringArray(rawAttrs)) {
    throw new AccessControlError(`Invalid attributes.${detail(safe, action)}`, {
      code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_GRANT),
      action
    });
  }
  const attributes = impliedStar(rawAttrs);

  const grant: IGrant = { attributes, possession: 'any' };

  if (r.possession !== undefined && r.possession !== null) {
    const p = String(r.possession).trim();
    if (possessions.indexOf(p) < 0) {
      throw new AccessControlError(`Invalid possession.${detail(safe, p)}`, {
        code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_ACTION),
        action
      });
    }
    grant.possession = p as 'own' | 'any';
  }

  if (r.effect !== undefined && r.effect !== null) {
    if (r.effect !== 'grant' && r.effect !== 'deny') {
      throw new AccessControlError(`Invalid effect.${detail(safe, action)}`, {
        code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_GRANT),
        action
      });
    }
    if (r.effect === 'deny') grant.effect = 'deny';
  }

  if (r.condition !== undefined && r.condition !== null) {
    grant.condition = compileCondition(r.condition, pathPrefix, opts.errorCodePrefix);
  }

  return grant;
}

/**
 * Validates and normalizes a resource definition (`action → IGrant[]`).
 */
function normalizeResourceGrants(
  raw: unknown,
  pathPrefix: string,
  opts: INameOptions
): IResourceGrants {
  const safe = opts.safeErrors !== false;
  if (type(raw) !== 'object') {
    throw new AccessControlError('Invalid resource definition.', {
      code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_GRANT)
    });
  }
  const out: IResourceGrants = {};
  eachKey(raw as UnknownObject, (action: string) => {
    // any valid name is a permitted action (charset-validated); CRUD is not
    // special. Possession lives in the rule, so the key must be a bare name.
    const act = normalizeName(action, false, opts);
    const rules = (raw as UnknownObject)[action];
    if (!Array.isArray(rules)) {
      throw new AccessControlError(
        `Invalid grant rules (expected an array).${detail(safe, action)}`,
        {
          code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_GRANT),
          action
        }
      );
    }
    out[act] = rules.map((rule) => normalizeGrant(rule, act, pathPrefix, opts));
  });
  return out;
}

/**
 * Inspects/normalizes a flat grants list into an `IGrants` model. Rule rows are
 * committed first; inheritance rows (`{ role, $extend }`) second — so an extended
 * role can be defined anywhere in the list (the fix).
 */
function inspectGrantsList(list: IGrantsList, pathPrefix: string, opts: INameOptions): IGrants {
  const grants: IGrants = {};
  list.forEach((item: IGrantsListItem) => {
    if (item && item.$extend === undefined) commitToGrants(grants, item, true, pathPrefix, opts);
  });
  list.forEach((item: IGrantsListItem) => {
    if (item && item.$extend !== undefined) {
      const role = normalizeName(item.role, true, opts);
      if (!Object.hasOwn(grants, role)) grants[role] = {};
      extendRole(
        grants,
        role,
        toStringArray(item.$extend).map((r: string) => normalizeName(r, true, opts)),
        opts
      );
    }
  });
  return grants;
}

/**
 * Inspects whether the given grants object/array has a valid structure and
 * returns a normalized `IGrants` model for internal use.
 * @throws {AccessControlError} - If the grants have an invalid structure.
 */
export function getInspectedGrants(
  o: unknown,
  pathPrefix: string = '$',
  opts: INameOptions = {}
): IGrants {
  const t = type(o);
  if (t === 'array') return inspectGrantsList(o as IGrantsList, pathPrefix, opts);
  if (t !== 'object') {
    throw new AccessControlError('Invalid grants object. Expected an array or object.', {
      code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_GRANT)
    });
  }

  const src = o as IGrants;
  const grants: IGrants = {};
  const pendingExtends: Array<{ role: string; ext: string[] }> = [];

  eachKey(src, (roleName: string) => {
    const role = normalizeName(roleName, true, opts);
    const roleObj = src[roleName];
    if (type(roleObj) !== 'object') {
      throw new AccessControlError(
        `Invalid role definition.${detail(opts.safeErrors !== false, role)}`,
        { code: ecode(opts.errorCodePrefix, ErrorCode.INVALID_GRANT), role }
      );
    }
    /* istanbul ignore next -- defensive: each role key is processed once */
    if (!Object.hasOwn(grants, role)) grants[role] = {};

    eachKey(roleObj as UnknownObject, (key: string) => {
      if (key === EXTEND_KEY) {
        const ext = toStringArray((roleObj as IGrantsItem).$extend).map((r: string) =>
          normalizeName(r, true, opts)
        );
        if (ext.length > 0) pendingExtends.push({ role, ext });
      } else {
        const resource = normalizeName(key, true, opts);
        grants[role][resource] = normalizeResourceGrants(
          (roleObj as UnknownObject)[key],
          pathPrefix,
          opts
        );
      }
    });
  });

  // apply inheritance after all roles exist (validates existence + cross-extend)
  pendingExtends.forEach(({ role, ext }) => {
    extendRole(grants, role, ext, opts);
  });
  return grants;
}

/**
 * Gets all the unique resources granted access for at least one role.
 */
export function getResources(grants: IGrants): string[] {
  const resources: UnknownObject = {};
  eachRoleResource(grants, (_role: string, resource: string) => {
    resources[resource] = null;
  });
  return Object.keys(resources);
}

/**
 * Gets all unique action names that appear anywhere in the grants model (the
 * strict-mode known-actions set).
 */
export function getActions(grants: IGrants, roles?: string[]): string[] {
  const out: UnknownObject = {};
  eachRoleResource(grants, (role: string, _resource: string, resInfo: IResourceGrants) => {
    if (roles && !roles.includes(role)) return;
    eachKey(resInfo, (action: string) => {
      out[action] = null;
    });
  });
  return Object.keys(out);
}

/**
 * Serializes the internal grants object into the flat **grants list** form (the
 * DB-friendly shape) — the inverse of {@link inspectGrantsList}. Each grant
 * rule becomes a row (`{ role, resource, action, possession, attributes,
 * condition?, effect? }`) and each role's `$extend` becomes one inheritance row
 * (`{ role, $extend }`). Round-trips: feeding the result back to AccessControl
 * reproduces the same model.
 */
export function toGrantsList(grants: IGrants): IGrantsList {
  const list: IGrantsListItem[] = [];
  eachKey(grants, (role: string) => {
    const roleObj = grants[role];
    const ext = (roleObj as IGrantsItem).$extend;
    if (Array.isArray(ext) && ext.length > 0) list.push({ role, $extend: [...ext] });

    eachKey(roleObj as UnknownObject, (key: string) => {
      if (key === EXTEND_KEY) return;
      const resourceGrants = (roleObj as UnknownObject)[key] as IResourceGrants;
      eachKey(resourceGrants, (action: string) => {
        const rules = resourceGrants[action];
        /* istanbul ignore next -- defensive: action values are always rule arrays */
        if (!Array.isArray(rules)) return;
        rules.forEach((rule: IGrant) => {
          /* istanbul ignore next -- defensive: stored rules always carry a possession */
          const possession = rule.possession ?? 'any';
          const row: IGrantsListItem = {
            role,
            resource: key,
            action,
            possession,
            attributes: [...rule.attributes]
          };
          if (rule.condition !== undefined) row.condition = structuredClone(rule.condition);
          if (rule.effect === 'deny') row.effect = 'deny';
          list.push(row);
        });
      });
    });
  });
  return list;
}

/**
 * Commits the given access info to the grants model by pushing an `IGrant` rule
 * onto `grants[role][resource][action]` (an array — Option B, multiple rules
 * per action). Omitted attributes default to `['*']`.
 *
 * @param grants
 * @param access
 * @param normalizeAll - Also validate/normalize `action`/`possession` (used for
 * flat list rows; the builder sets these itself).
 * @throws {AccessControlError} - If the access info fails validation.
 */
export function commitToGrants(
  grants: IGrants,
  access: IAccessInfo | IGrantsListItem,
  normalizeAll: boolean = false,
  pathPrefix: string = '$',
  opts: INameOptions = {}
) {
  const ai = normalizeAccessInfo(access, normalizeAll, opts);
  // Always validate the action used as a storage key — even on the builder path
  // (normalizeAll=false). This rejects reserved/invalid action names (e.g. a
  // custom `.action('__proto__', …)`) before they reach the grants map.
  const action = normalizeName(ai.action as string, false, opts);
  const possession = ((ai.possession as 'own' | 'any') ?? 'any') as 'own' | 'any';
  // Compile to canonical JSON up front so dedup (condKey) and storage compare
  // equivalent conditions consistently.
  const condition =
    ai.condition === undefined
      ? undefined
      : compileCondition(ai.condition, pathPrefix, opts.errorCodePrefix);

  (ai.role as string[]).forEach((role: string) => {
    if (!Object.hasOwn(grants, role)) grants[role] = {};
    const roleItem = grants[role];

    const effect: 'grant' | 'deny' = ai.denied ? 'deny' : 'grant';
    const condKey = condition === undefined ? '' : JSON.stringify(condition);

    (ai.resource as string[]).forEach((res: string) => {
      if (!Object.hasOwn(roleItem, res)) roleItem[res] = {};
      const resItem = roleItem[res] as IResourceGrants;
      if (!Array.isArray(resItem[action])) resItem[action] = [];

      // Re-granting the same (possession + effect + condition) replaces its
      // attributes (last-write-wins). Rules with a different condition coexist
      // as separate entries (multiple conditional rules per action).
      const existing = resItem[action].find(
        /* istanbul ignore next -- defensive `?? default`s: stored rules are normalized */
        (g: IGrant) =>
          (g.possession ?? 'any') === possession &&
          (g.effect ?? 'grant') === effect &&
          (g.condition === undefined ? '' : JSON.stringify(g.condition)) === condKey
      );

      if (existing) {
        existing.attributes = toStringArray(ai.attributes);
      } else {
        const grant: IGrant = { attributes: toStringArray(ai.attributes), possession };
        if (condition !== undefined) grant.condition = condition;
        if (effect === 'deny') grant.effect = 'deny';
        resItem[action].push(grant);
      }
    });
  });
}

/**
 * Subtracts denied attributes from allowed ones (deny-overrides) using
 * glob-aware negation + normalization. e.g. allow `['*']` minus deny `['x']`
 * → `['*','!x']`; allow `['*']` minus deny `['*']` → `[]`. Inputs are assumed
 * already unioned (see {@link getUnionAttrsOfRoles}).
 */
function subtractAttributes(allowed: string[], denied: string[]): string[] {
  if (allowed.length === 0) return [];
  if (denied.length === 0) return allowed;
  /* istanbul ignore next -- denied lists here are plain (un-negated) attributes */
  const negated = denied.map((a: string) => (a.startsWith('!') ? a.slice(1) : '!' + a));
  return NotationGlob.normalize(allowed.concat(negated));
}

/**
 * Determines whether an `own`-possession rule applies for this check.
 *
 * Precedence: a custom `owner(ctx)` resolver wins (truthy ⇒ owned); otherwise
 * the `ownerField` convention compares `context.user.id` to
 * `context.<resource>[ownerField]`. With **no resolver configured**, ownership
 * is not enforced — the `own` rule applies as in v2 (option (b)). When a
 * resolver *is* configured but ownership can't be verified (record or owner
 * missing), `strict.checks` (default `true`) denies it.
 */
function ownsRecord(ctx: UnknownObject, resource: string, options?: IResolveOptions): boolean {
  if (typeof options?.owner === 'function') return options.owner(ctx) === true;
  const ownerField = options?.ownerField;
  if (!ownerField) return true; // no resolver ⇒ no ownership gate (v2)
  const strict = options?.strictChecks !== false; // default true
  // prototype-safe: only an own context property counts as the record (a
  // resource named like an inherited member must not read e.g. ctx.toString)
  const record = (Object.hasOwn(ctx, resource) ? ctx[resource] : undefined) as
    | UnknownObject
    | undefined;
  const user = ctx.user as UnknownObject | undefined;
  const ownerId = record == null ? undefined : record[ownerField];
  const userId = user == null ? undefined : user.id;
  if (ownerId === undefined || userId === undefined) return !strict; // unverifiable
  return userId === ownerId;
}

/** Resolved per-check scope shared by the sync and async resolvers. */
interface ResolutionScope {
  queriedRoles: string[];
  resource: string;
  action: string;
  possession: 'own' | 'any';
  pathPrefix: string;
  baseContext: UnknownObject;
  strictRoles: boolean;
  /** Whether the `matches` regex operator is permitted (policy.allowRegex). */
  allowRegex: boolean;
  /** Charset / safe-errors policy threaded into name validation + messages. */
  nameOpts: INameOptions;
  category?: string;
  resourceKeys: string[];
  knownRoles: Set<string>;
  /** Applicable require() gates (global + category + resource), pre-collected. */
  gates: ConditionJSON[];
  /** Context used to evaluate the require() gates. */
  gateCtx: UnknownObject;
}

/**
 * Reads a requirement bucket prototype-safely: returns the bucket's **own**
 * gate array for `key`, or `[]` for any key that isn't an own property (so an
 * inherited member name like `toString` can never surface a function here and
 * crash the gate spread).
 */
function ownGates(bucket: Record<string, ConditionJSON[]>, key: string): ConditionJSON[] {
  return Object.hasOwn(bucket, key) ? bucket[key] : [];
}

/**
 * Validates the query, runs the `strict` typo-protection throws, and computes
 * the per-check scope (categories, role known-set, applicable require() gates)
 * shared by {@link getUnionAttrsOfRoles} and its async sibling.
 */
function prepareResolution(
  grants: IGrants,
  query: IQueryInfo,
  options?: IResolveOptions
): ResolutionScope {
  const nameOpts: INameOptions = {
    charset: options?.charset,
    safeErrors: options?.safeErrors,
    errorCodePrefix: options?.errorCodePrefix
  };
  const safe = options?.safeErrors !== false;
  query = normalizeQueryInfo(query, nameOpts);
  const queriedRoles = query.role as string[];
  const resource = query.resource as string;
  const action = query.action as string;
  const possession = query.possession as 'own' | 'any';
  const pathPrefix = options?.pathPrefix ?? '$';
  const baseContext = options?.context ?? {};
  const strictRoles = options?.strictRoles !== false; // default true
  const allowRegex = options?.allowRegex === true; // default false (opt-in)

  // optional typo-protection — throw on an unknown action/resource
  // instead of silently returning granted:false. Known sets derive from the
  // grants (+ CRUD for actions, + declared vocabulary, + explicit policy lists).
  if (options?.strictActions) {
    /* istanbul ignore next -- optional vocab/policy lists default to [] */
    const extra = [...(options.vocabActions ?? []), ...(options.policyActions ?? [])];
    const known = new Set([...actions, ...getActions(grants), ...extra]);
    if (!known.has(action)) {
      throw new AccessControlError(`Unknown action (strict.actions).${detail(safe, action)}`, {
        code: ecode(nameOpts.errorCodePrefix, ErrorCode.UNKNOWN_ACTION),
        action
      });
    }
  }
  if (options?.strictResources) {
    /* istanbul ignore next -- optional vocab/policy lists default to [] */
    const extra = [...(options.vocabResources ?? []), ...(options.policyResources ?? [])];
    const known = new Set([...getResources(grants), ...extra]);
    if (!known.has(resource)) {
      throw new AccessControlError(
        `Unknown resource (strict.resources).${detail(safe, resource)}`,
        {
          code: ecode(nameOpts.errorCodePrefix, ErrorCode.UNKNOWN_RESOURCE),
          resource
        }
      );
    }
  }

  // resource categories: a qualified `category/resource` check also reads
  // grants made at the category level (dynamic bulk grant). Bare resources are
  // unaffected (backward compatible).
  const category = resource.includes(GROUP_SEPARATOR)
    ? resource.split(GROUP_SEPARATOR)[0]
    : undefined;
  const resourceKeys = category ? [resource, category] : [resource];
  const knownRoles = new Set(options?.vocabRoles ?? []);

  // require() gates — applicable = global + the resource's category + the
  // resource itself. Collected here; evaluated by the caller (sync or async).
  const req = options?.requirements;
  // Prototype-safe lookups: a resource/category named like an inherited Object
  // member (`toString`, `valueOf`, `constructor`, …) must read as "no gates",
  // not the inherited function (which would throw on spread). See ownGates.
  const gates: ConditionJSON[] = req
    ? [
        ...req.global,
        ...(category ? ownGates(req.categories, category) : []),
        ...ownGates(req.resources, resource)
      ]
    : [];
  const gateCtx: UnknownObject = {
    ...baseContext,
    roles: queriedRoles,
    resource,
    action,
    possession,
    category
  };

  return {
    queriedRoles,
    resource,
    action,
    possession,
    pathPrefix,
    baseContext,
    strictRoles,
    allowRegex,
    nameOpts,
    category,
    resourceKeys,
    knownRoles,
    gates,
    gateCtx
  };
}

/**
 * For a single queried role, resolves its flattened node set (self + dynamic
 * group, each via `$extend`) and the per-role evaluation context. Returns `null`
 * when the role contributes nothing (unknown-but-lenient, or known-but-ungranted);
 * throws under `strict.roles` for a genuinely unknown role.
 */
function collectRoleResolution(
  qr: string,
  grants: IGrants,
  s: ResolutionScope
): { ctx: UnknownObject; flat: Set<string> } | null {
  const group = qr.includes(GROUP_SEPARATOR) ? qr.split(GROUP_SEPARATOR)[0] : undefined;
  const selfHas = Object.hasOwn(grants, qr);
  const groupHas = !!group && Object.hasOwn(grants, group);

  if (!selfHas && !groupHas) {
    const isKnown = s.knownRoles.has(qr) || (!!group && s.knownRoles.has(group));
    if (s.strictRoles && !isKnown) {
      throw new AccessControlError(
        `Role not found.${detail(s.nameOpts.safeErrors !== false, qr)}`,
        {
          code: ecode(s.nameOpts.errorCodePrefix, ErrorCode.ROLE_NOT_FOUND),
          role: qr
        }
      );
    }
    return null;
  }

  // query metadata wins over caller context (no spoofing what you check).
  const ctx: UnknownObject = {
    ...s.baseContext,
    role: qr,
    roles: s.queriedRoles,
    resource: s.resource,
    action: s.action,
    possession: s.possession,
    category: s.category
  };
  const flat = new Set<string>();
  if (selfHas) {
    getRoleHierarchyOf(grants, qr, s.nameOpts).forEach((r: string) => {
      flat.add(r);
    });
  }
  if (groupHas) {
    getRoleHierarchyOf(grants, group as string, s.nameOpts).forEach((r: string) => {
      flat.add(r);
    });
  }
  return { ctx, flat };
}

/** Diagnostic flags accumulated across a resolution, used to derive a reason. */
interface ResolveFlags {
  /** A rule existed for the (resource, action) — i.e. something was a candidate. */
  candidate: boolean;
  /** A candidate rule's `condition` failed. */
  condFail: boolean;
  /** An `own` rule was skipped because ownership wasn't verified. */
  ownFail: boolean;
  /** A grant rule with `any` possession contributed to the allowed set. */
  grantAny: boolean;
}

/**
 * Folds a single (already condition-filtered) rule into the allow/deny
 * accumulator: possession cascade for grants (`any` ⊇ `own`), strict possession
 * match for denies, and the `own` ownership gate. Pure & sync.
 */
function applyRule(
  rule: IGrant,
  s: ResolutionScope,
  ctx: UnknownObject,
  options: IResolveOptions | undefined,
  acc: { allowed: string[]; denied: string[] },
  flags: ResolveFlags
): void {
  /* istanbul ignore next -- defensive: stored rules always have a possession */
  const rPoss = rule.possession ?? 'any';
  if (s.possession === 'own' && rPoss === 'own' && !ownsRecord(ctx, s.resource, options)) {
    flags.ownFail = true;
    return;
  }
  if (rule.effect === 'deny') {
    if (rPoss === s.possession) acc.denied = NotationGlob.union(acc.denied, rule.attributes);
  } else {
    const applies = s.possession === 'any' ? rPoss === 'any' : true;
    if (applies) {
      acc.allowed = NotationGlob.union(acc.allowed, rule.attributes);
      if (rPoss === 'any') flags.grantAny = true;
    }
  }
}

/** Unions the per-role attribute results into the final effective set. */
function unionPerRole(perRole: string[][]): string[] {
  if (perRole.length === 0) return [];
  let attrs = perRole[0];
  for (let i = 1; i < perRole.length; i++) attrs = NotationGlob.union(attrs, perRole[i]);
  return attrs;
}

/** Whether an attribute set grants access (≥1 non-negated attribute). */
function hasGrant(attributes: string[]): boolean {
  return attributes.length > 0 && attributes.some((a) => a.trim().slice(0, 1) !== '!');
}

/** Derives the denial reason from the final attributes + diagnostic flags. */
function reasonFor(attributes: string[], flags: ResolveFlags): AccessReason | undefined {
  if (hasGrant(attributes)) return undefined;
  if (!flags.candidate) return 'no_grant';
  if (flags.ownFail) return 'ownership_failed';
  if (flags.condFail) return 'condition_failed';
  return 'no_grant';
}

/**
 * The possession that *effectively* grants access. Since `any` ⊇ `own`, an `any`
 * grant wins when one applied; otherwise an applied `own` grant. On denial there
 * is no granting possession, so the requested one is echoed back.
 */
function possessionFor(
  attributes: string[],
  requested: 'own' | 'any',
  flags: ResolveFlags
): 'own' | 'any' {
  if (!hasGrant(attributes)) return requested;
  return flags.grantAny ? 'any' : 'own';
}

/** The result of a resolution: effective attributes, denial reason, possession. */
export interface ResolveResult {
  attributes: string[];
  reason?: AccessReason;
  /** The possession that effectively granted access (the requested one on denial). */
  possession: 'own' | 'any';
}

/**
 * Resolves the effective attributes (+ denial reason) for the given query
 * — synchronous.
 *
 * Per queried role chain: union granted attributes, subtract denied attributes
 * (deny-overrides). Grants cascade across possession (`any` ⊇ `own`); denies do
 * not. Finally, union the per-chain results across all queried roles.
 *
 * A rule whose `condition` fails for the check context is dropped from the
 * applicability set. An `own`-possession rule additionally requires
 * verified ownership. A custom/async `{ fn }` condition throws
 * `asyncRequired` — use {@link resolveAccessAsync}.
 *
 * @param grants
 * @param query
 * @param options - Resolved engine options (path prefix, context, ownership,
 * strict, vocabulary, require() gates). Query metadata is injected after the
 * caller context, so it always wins.
 */
export function resolveAccess(
  grants: IGrants,
  query: IQueryInfo,
  options?: IResolveOptions
): ResolveResult {
  const s = prepareResolution(grants, query, options);

  if (s.gates.length > 0) {
    if (
      !s.gates.every((g) =>
        evaluateCondition(g, s.gateCtx, s.pathPrefix, s.allowRegex, s.nameOpts.errorCodePrefix)
      )
    ) {
      return { attributes: [], reason: 'require_failed', possession: s.possession };
    }
  }

  const flags: ResolveFlags = {
    candidate: false,
    condFail: false,
    ownFail: false,
    grantAny: false
  };
  const perRole: string[][] = [];
  for (const qr of s.queriedRoles) {
    const r = collectRoleResolution(qr, grants, s);
    if (!r) continue;
    const acc = { allowed: [] as string[], denied: [] as string[] };
    for (const roleName of r.flat) {
      for (const resKey of s.resourceKeys) {
        const rules = (grants[roleName]?.[resKey] as IResourceGrants | undefined)?.[s.action];
        if (!Array.isArray(rules)) continue;
        for (const rule of rules) {
          flags.candidate = true;
          if (
            rule.condition !== undefined &&
            !evaluateCondition(
              rule.condition,
              r.ctx,
              s.pathPrefix,
              s.allowRegex,
              s.nameOpts.errorCodePrefix
            )
          ) {
            flags.condFail = true;
            continue;
          }
          applyRule(rule, s, r.ctx, options, acc, flags);
        }
      }
    }
    perRole.push(subtractAttributes(acc.allowed, acc.denied));
  }
  const attributes = unionPerRole(perRole);
  return {
    attributes,
    reason: reasonFor(attributes, flags),
    possession: possessionFor(attributes, s.possession, flags)
  };
}

/**
 * Async sibling of {@link resolveAccess}. Identical resolution, but
 * `await`s any custom `{ fn }` conditions (rules and require() gates) against the
 * registered condition functions (`options.conditions`).
 */
export async function resolveAccessAsync(
  grants: IGrants,
  query: IQueryInfo,
  options?: IResolveOptions
): Promise<ResolveResult> {
  const s = prepareResolution(grants, query, options);
  const registry = options?.conditions ?? {};

  for (const g of s.gates) {
    if (
      !(await evaluateConditionAsync(
        g,
        s.gateCtx,
        s.pathPrefix,
        registry,
        s.allowRegex,
        s.nameOpts.errorCodePrefix
      ))
    ) {
      return { attributes: [], reason: 'require_failed', possession: s.possession };
    }
  }

  const flags: ResolveFlags = {
    candidate: false,
    condFail: false,
    ownFail: false,
    grantAny: false
  };
  const perRole: string[][] = [];
  for (const qr of s.queriedRoles) {
    const r = collectRoleResolution(qr, grants, s);
    if (!r) continue;
    const acc = { allowed: [] as string[], denied: [] as string[] };
    for (const roleName of r.flat) {
      for (const resKey of s.resourceKeys) {
        const rules = (grants[roleName]?.[resKey] as IResourceGrants | undefined)?.[s.action];
        if (!Array.isArray(rules)) continue;
        for (const rule of rules) {
          flags.candidate = true;
          if (
            rule.condition !== undefined &&
            !(await evaluateConditionAsync(
              rule.condition,
              r.ctx,
              s.pathPrefix,
              registry,
              s.allowRegex,
              s.nameOpts.errorCodePrefix
            ))
          ) {
            flags.condFail = true;
            continue;
          }
          applyRule(rule, s, r.ctx, options, acc, flags);
        }
      }
    }
    perRole.push(subtractAttributes(acc.allowed, acc.denied));
  }
  const attributes = unionPerRole(perRole);
  return {
    attributes,
    reason: reasonFor(attributes, flags),
    possession: possessionFor(attributes, s.possession, flags)
  };
}
