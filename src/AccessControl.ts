import { Access, AccessControlError, Emitter, Permission, Query } from './core/index.js';
import { type AccessControlEvent, Charset, ErrorCode } from './enums/index.js';
import type {
  AccessControlEventName,
  ChangeType,
  ConditionFunction,
  ConditionJSON,
  EventListener,
  IAccessControlOptions,
  IAccessInfo,
  IGrants,
  IGrantsItem,
  IGrantsList,
  IQueryInfo,
  IRequirements,
  IResolveOptions,
  ISetup,
  ISnapshot,
  OwnerResolver,
  UnknownObject
} from './types/index.js';
import {
  compileCondition,
  deepFreeze,
  detail,
  ERR_LOCK,
  eachRole,
  eachRoleResource,
  ecode,
  extendRole,
  filterAll,
  GROUP_SEPARATOR,
  GROUP_UNGROUPED,
  getActions,
  getInspectedGrants,
  getResources,
  getRoleHierarchyOf,
  type INameOptions,
  isFilledStringArray,
  lockAC,
  NAME_RE,
  NAME_RE_UNICODE,
  normalizeName,
  subtractArray,
  toGrantsList,
  toStringArray,
  type
} from './utils/index.js';

/**
 * AccessControl class that implements RBAC (Role-Based Access Control) basics
 * and ABAC (Attribute-Based Access Control) <i>resource</i> and <i>action</i>
 * attributes.
 *
 * Construct an `AccessControl` instance by either passing a grants object (or
 * array fetched from database) or simply omit `grants` parameter if you are
 * willing to build it programmatically.
 *
 * ```js
 * const grants = {
 *   role1: {
 *     resource1: {
 *       create: [{ possession: 'any', attributes: ['*'] }],
 *       read: [{ possession: 'own', attributes: ['*'] }]
 *     },
 *     resource2: {
 *       update: [{ possession: 'own', attributes: ['*', '!secret'] }]
 *     }
 *   },
 *   role2: { ... }
 * };
 * const ac = new AccessControl(grants);
 * ```
 *
 * The `grants` can also be an array, such as a flat list fetched from a
 * database. Rule rows carry `action` (optionally with possession via the
 * `:own`/`:any` convention) and inheritance travels as `{ role, $extend }` rows
 * (same keyword as the object form).
 *
 * ```js
 * const flatList = [
 *   { role: 'role1', resource: 'resource1', action: 'create:any', attributes: ['*'] },
 *   { role: 'role1', resource: 'resource1', action: 'read:own', attributes: ['*'] },
 *   { role: 'role2', $extend: ['role1'] }
 * ];
 * const ac = new AccessControl(flatList);
 * ```
 *
 * In the internal model, each `action` maps to an **array** of grant rules
 * (`{ attributes, possession?, condition?, effect? }`); possession omitted
 * defaults to `'any'`.
 *
 * @author   Onur Yıldırım <onur@cutepilot.com>
 * @license  MIT
 *
 * @example
 * const ac = new AccessControl(grants);
 *
 * ac.grant('admin').createAny('profile');
 *
 * // or you can chain methods
 * ac.grant('admin')
 *     .createAny('profile')
 *     .readAny('profile', ["*", "!password"])
 *     .readAny('video')
 *     .deleteAny('video');
 *
 * // since these permissions have common resources, there is an alternative way:
 * ac.grant('admin')
 *     .resource('profile').createAny().readAny(undefined, ["*", "!password"])
 *     .resource('video').readAny().deleteAny();
 *
 * ac.grant('user')
 *     .readOwn('profile', ["uid", "email", "address.*", "account.*", "!account.roles"])
 *     .updateOwn('profile', ["uid", "email", "password", "address.*", "!account.roles"])
 *     .deleteOwn('profile')
 *     .createOwn('video', ["*", "!geo.*"])
 *     .readAny('video')
 *     .updateOwn('video', ["*", "!geo.*"])
 *     .deleteOwn('video');
 *
 * // now we can check for granted or denied permissions
 * const permission = ac.can('admin').readAny('profile');
 * permission.granted // true
 * permission.attributes // ["*", "!password"]
 * permission.filter(data) // { uid, email, address, account }
 * // deny permission
 * ac.deny('admin').createAny('profile');
 * ac.can('admin').createAny('profile').granted; // false
 *
 * // To add a grant but deny access via attributes
 * ac.grant('admin').createAny('profile', []); // no attributes allowed
 * ac.can('admin').createAny('profile').granted; // false
 *
 * // To prevent any more changes:
 * ac.lock();
 */
export class AccessControl {
  /**
   * @private
   */
  private _grants: IGrants = {};

  /**
   * @private
   */
  private _isLocked: boolean = false;

  /**
   * Resolved engine policy (constructor-only): condition path sentinel and the
   * ownership/strict settings the engine reads at check time.
   * @private
   */
  private _policy!: {
    pathPrefix: string;
    ownerField?: string;
    owner?: OwnerResolver;
    strictChecks: boolean;
    strictRoles: boolean;
    strictActions: boolean;
    strictResources: boolean;
    actions?: string[];
    resources?: string[];
    allowRegex: boolean;
    charset: RegExp;
    safeErrors: boolean;
    errorCodePrefix: string;
  };

  /**
   * Ambient context defaults, merged with (and overridden by) per-check context.
   * @private
   */
  private _context: UnknownObject = {};

  /**
   * Declared role **groups**: group name → qualified member roles
   * (`admins` → `['admins/admin', 'admins/moderator']`). Built by `setup()`.
   * @private
   */
  private _groups: Record<string, string[]> = {};

  /**
   * Declared resource **categories**: category name → qualified member
   * resources (`media` → `['media/photo', 'media/video']`). Built by `setup()`.
   * @private
   */
  private _categories: Record<string, string[]> = {};

  /**
   * Declared action vocabulary, feeding the `strict.actions` known set.
   * @private
   */
  private _vocabActions: string[] = [];

  /**
   * Compiled mandatory restriction gates by scope. Every applicable gate
   * must pass for a check to be granted — `require()` can only restrict.
   * @private
   */
  private _requirements: IRequirements = { global: [], categories: {}, resources: {} };

  /**
   * Registered custom condition functions, referenced from grants as
   * `{ fn: name, args }` and evaluated on the async check path.
   * @private
   */
  private _conditions: Record<string, ConditionFunction> = {};

  /**
   * Internal observational event emitter. Listeners are registered via
   * `on`/`once`/`off`.
   * @private
   */
  private readonly _emitter = new Emitter();

  /**
   * Initializes a new instance of `AccessControl` with the given grants and
   * optional engine `policy` / ambient `context`.
   *
   * @param [grants] - A list/object of access grant definitions. See the
   * structure of this object in the examples.
   * @param [options] - `{ engine, policy, context }`.
   * **`engine`** configures library mechanics & security (`pathPrefix`,
   * `allowRegex`, `charset`, `safeErrors`); **`policy`** configures your
   * authorization model (`ownerField`/`owner`, `strict`, action/resource
   * allow-lists); **`context`** supplies ambient data readable from conditions
   * via `$.`.
   */
  constructor(grants: IGrantsList | IGrants = {}, options: IAccessControlOptions = {}) {
    // explicit undefined is not allowed
    if (arguments.length === 0) grants = {};
    const e = options.engine ?? {};
    const p = options.policy ?? {};
    // `strict` is a boolean OR an object; resolve to per-key flags.
    // Defaults: checks/roles on (secure), actions/resources off (lenient) so an
    // ungranted action/resource returns granted:false instead of throwing.
    const s = p.strict;
    const strict =
      s === true
        ? { checks: true, roles: true, actions: true, resources: true }
        : s === false
          ? { checks: false, roles: false, actions: false, resources: false }
          : {
              checks: s?.checks ?? true,
              roles: s?.roles ?? true,
              actions: s?.actions ?? false,
              resources: s?.resources ?? false
            };
    this._policy = {
      pathPrefix: e.pathPrefix ?? '$',
      ownerField: p.ownerField,
      owner: p.owner,
      strictChecks: strict.checks,
      strictRoles: strict.roles,
      strictActions: strict.actions,
      strictResources: strict.resources,
      actions: p.actions,
      resources: p.resources,
      allowRegex: e.allowRegex === true,
      charset: e.charset === Charset.UNICODE ? NAME_RE_UNICODE : NAME_RE,
      safeErrors: e.safeErrors !== false,
      errorCodePrefix: e.errorCodePrefix ?? ''
    };
    this._context = options.context ? { ...options.context } : {};
    this.setGrants(grants);
  }

  // -------------------------------
  //  PUBLIC PROPERTIES
  // -------------------------------

  /**
   * Specifies whether the underlying grants object is frozen and all
   * functionality for modifying it is disabled.
   */
  get isLocked(): boolean {
    return this._isLocked && Object.isFrozen(this._grants);
  }

  // -------------------------------
  //  PUBLIC METHODS
  // -------------------------------

  /**
   * Gets the internal grants object that stores all current grants.
   *
   * @return - Hash-map of grants.
   *
   * @example
   * ac.grant('admin')
   *     .createAny(['profile', 'video'])
   *     .deleteAny(['profile', 'video'])
   *     .readAny(['video'])
   *     .readAny('profile', ['*', '!password'])
   *     .grant('user')
   *     .readAny(['profile', 'video'], ['*', '!id', '!password'])
   *     .createOwn(['profile', 'video'])
   *     .deleteOwn(['video']);
   * // logging underlying grants model
   * console.log(ac.getGrants());
   * // outputs:
   * {
   *   "admin": {
   *     "profile": {
   *       "create": [{ "possession": "any", "attributes": ["*"] }],
   *       "delete": [{ "possession": "any", "attributes": ["*"] }],
   *       "read": [{ "possession": "any", "attributes": ["*", "!password"] }]
   *     },
   *     "video": {
   *       "create": [{ "possession": "any", "attributes": ["*"] }],
   *       "read": [{ "possession": "any", "attributes": ["*"] }]
   *     }
   *   },
   *   "user": {
   *     "profile": {
   *       "read": [{ "possession": "any", "attributes": ["*", "!id", "!password"] }],
   *       "create": [{ "possession": "own", "attributes": ["*"] }]
   *     }
   *   }
   * }
   */
  getGrants(): IGrants {
    // return a frozen deep clone so external code cannot mutate the internal
    // grants model (the live reference stays mutable for internal use).
    return deepFreeze(structuredClone(this._grants)) as IGrants;
  }

  /**
   * Serializes all grants to the flat **grants list** form — the
   * DB-friendly shape and the inverse of the object returned by
   * {@link AccessControl#getGrants}. Each grant rule becomes a row
   * (`{ role, resource, action, possession, attributes, condition?, effect? }`)
   * and each role's inheritance becomes one `{ role, $extend }` row. Feeding the
   * result back (constructor or `setGrants`) reproduces the same model.
   *
   * @returns - The grants as a flat list of rows.
   *
   * @example
   * const rows = ac.getGrantsList();
   * await db.saveGrants(rows);
   * const restored = new AccessControl(rows);
   */
  getGrantsList(): IGrantsList {
    return toGrantsList(this._grants);
  }

  /**
   * Sets all access grants at once, from an object or array. Note that this
   * will reset the object and remove all previous grants.
   * @param grantsObject - A list containing the access grant definitions.
   *
   * @returns - `AccessControl` instance for chaining.
   * @throws {AccessControlError} - If called after `.lock()` is called or if
   * passed grants object fails inspection.
   */
  setGrants(grantsObject: IGrantsList | IGrants): AccessControl {
    if (this.isLocked)
      throw new AccessControlError(ERR_LOCK, {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.LOCKED)
      });
    this._grants = getInspectedGrants(grantsObject, this._policy.pathPrefix, this._nameOpts());
    this._emitChange('set_grants');
    return this;
  }

  /**
   * Charset / safe-errors policy threaded into the name-validation helpers.
   * @private
   */
  _nameOpts(): INameOptions {
    return {
      charset: this._policy.charset,
      safeErrors: this._policy.safeErrors,
      errorCodePrefix: this._policy.errorCodePrefix
    };
  }

  /**
   * Declares the **vocabulary** — which role groups, resource categories and
   * custom actions exist. `setup()` declares vocabulary; `grant()`
   * declares permissions. Members listed under a group/category become
   * `group/member`-qualified names; the reserved `_` key lists ungrouped /
   * uncategorized members. Chainable and additive (call it more than once).
   *
   * Groups/categories power **bounded bulk grants** (`grant('admins')` on
   * `'media'` reaches every member × every member), dynamic shared base
   * (members inherit a group's grants at check time) and `strict` typo-checks.
   *
   * @param vocab - `{ roles, resources, actions }`.
   * @returns - `AccessControl` instance for chaining.
   * @throws {AccessControlError} - If locked or a declared name is invalid.
   *
   * @example
   * ac.setup({
   *   roles:     { admins: ['admin', 'moderator'], _: ['user'] },
   *   resources: { media: ['photo', 'video'], _: ['profile'] },
   *   actions:   ['publish'],
   * });
   */
  setup(vocab: ISetup): AccessControl {
    if (this.isLocked)
      throw new AccessControlError(ERR_LOCK, {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.LOCKED)
      });
    if (type(vocab) !== 'object') {
      throw new AccessControlError('Invalid setup vocabulary, expected an object.', {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.INVALID_SETUP)
      });
    }
    if (vocab.roles) this._declareVocab(this._asVocabMap(vocab.roles), this._groups);
    if (vocab.resources) this._declareVocab(this._asVocabMap(vocab.resources), this._categories);
    if (vocab.actions) {
      toStringArray(vocab.actions).forEach((a: string) => {
        const action = normalizeName(a, false, this._nameOpts());
        if (!this._vocabActions.includes(action)) this._vocabActions.push(action);
      });
    }
    this._emitChange('setup');
    return this;
  }

  /**
   * Declares a `{ group: members }` vocabulary map into the given store,
   * producing qualified `group/member` names. The reserved `_` key lists
   * ungrouped members (kept under `_` for introspection).
   * @private
   */
  /**
   * Normalizes a `setup()` `roles`/`resources` value: a plain array is treated
   * as ungrouped members (the `_` bucket); a map is used as-is.
   * @private
   */
  private _asVocabMap(value: string[] | Record<string, string[]>): Record<string, string[]> {
    return Array.isArray(value) ? { [GROUP_UNGROUPED]: value } : value;
  }

  private _declareVocab(map: Record<string, string[]>, store: Record<string, string[]>): void {
    Object.keys(map).forEach((rawKey: string) => {
      const key =
        rawKey === GROUP_UNGROUPED
          ? GROUP_UNGROUPED
          : normalizeName(rawKey, false, this._nameOpts());
      const members = toStringArray(map[rawKey]).map((m: string) => {
        const name = normalizeName(m, false, this._nameOpts());
        return key === GROUP_UNGROUPED ? name : `${key}${GROUP_SEPARATOR}${name}`;
      });
      // prototype-safe init: an inherited key (e.g. a category named `toString`)
      // would otherwise read a function here and crash the push below.
      if (!Object.hasOwn(store, key)) store[key] = [];
      const bucket = store[key];
      members.forEach((m: string) => {
        if (!bucket.includes(m)) bucket.push(m);
      });
    });
  }

  /** Strict known-roles set: qualified members + ungrouped + group names. */
  private _vocabRoleNames(): string[] {
    return this._flattenVocab(this._groups);
  }

  /** Strict known-resources set: qualified members + uncategorized + categories. */
  private _vocabResourceNames(): string[] {
    return this._flattenVocab(this._categories);
  }

  /** Flattens a group/category store into `[node names..., members...]`. */
  private _flattenVocab(store: Record<string, string[]>): string[] {
    const out: string[] = [];
    Object.keys(store).forEach((key: string) => {
      if (key !== GROUP_UNGROUPED) out.push(key); // the group/category node itself
      store[key].forEach((m: string) => {
        out.push(m);
      });
    });
    return out;
  }

  /**
   * Introspects a declared role group.
   * @param name - Group name.
   * @returns - `{ getRoles() }` — the qualified member roles (a copy).
   */
  group(name: string): { getRoles(): string[] } {
    // prototype-safe: an undeclared name (incl. inherited keys like `toString`)
    // yields an empty group rather than reading an inherited member.
    const members = Object.hasOwn(this._groups, name) ? [...this._groups[name]] : [];
    return { getRoles: () => [...members] };
  }

  /**
   * Introspects a declared resource category and scopes category-level
   * `require()` gates.
   * @param name - Category name.
   * @returns - `{ getResources(), require() }`. `getResources()` returns the
   * qualified member resources (a copy); `require()` adds a mandatory gate that
   * must pass for any check on a resource in this category.
   */
  category(name: string): {
    getResources(): string[];
    require(condition: ConditionJSON): AccessControl;
  } {
    const cat = normalizeName(name, false, this._nameOpts());
    const members = Object.hasOwn(this._categories, name) ? [...this._categories[name]] : [];
    return {
      getResources: () => [...members],
      require: (condition: ConditionJSON) =>
        this._addRequirement(this._requirements.categories, cat, condition)
    };
  }

  /** Whether the given role **group** has been declared (via `setup()`). */
  hasGroup(name: string): boolean {
    return Object.hasOwn(this._groups, name);
  }

  /** Whether the given resource **category** has been declared (via `setup()`). */
  hasCategory(name: string): boolean {
    return Object.hasOwn(this._categories, name);
  }

  /**
   * Scopes mandatory `require()` gates to a single resource.
   * @param name - Resource name (a `category/resource` qualifier is allowed).
   * @returns - `{ require() }` — adds a gate that must pass for any check on
   * this resource.
   */
  resource(name: string): { require(condition: ConditionJSON): AccessControl } {
    const res = normalizeName(name, true, this._nameOpts());
    return {
      require: (condition: ConditionJSON) =>
        this._addRequirement(this._requirements.resources, res, condition)
    };
  }

  /**
   * Adds a **global** mandatory restriction gate — evaluated on every
   * check. Unlike `.where()` (which conditionally *grants*), `.require()` can
   * only *restrict*: `granted = (a grant matches) AND (every applicable gate
   * passes)`. Adding a gate can never widen access.
   * @param condition - String-sugar or canonical-JSON condition (same engine as
   * `.where()`).
   * @returns - `AccessControl` instance for chaining.
   * @throws {AccessControlError} - If locked.
   *
   * @example
   * ac.require('$.env == "prod"'); // global
   * ac.category('billing').require('$.ip cidr 10.0.0.0/8');
   * ac.resource('billing/invoice').require('$.now.hour between [9, 18]');
   */
  require(condition: ConditionJSON): AccessControl {
    if (this.isLocked)
      throw new AccessControlError(ERR_LOCK, {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.LOCKED)
      });
    this._requirements.global.push(
      compileCondition(condition, this._policy.pathPrefix, this._policy.errorCodePrefix)
    );
    this._emitChange('require', { scope: 'global' });
    return this;
  }

  /**
   * Pushes a compiled gate into a scoped requirement bucket.
   * @private
   */
  private _addRequirement(
    bucket: Record<string, ConditionJSON[]>,
    key: string,
    condition: ConditionJSON
  ): AccessControl {
    if (this.isLocked)
      throw new AccessControlError(ERR_LOCK, {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.LOCKED)
      });
    // prototype-safe init: an inherited key (e.g. a resource named `toString`)
    // would otherwise read a function here and crash the push below.
    if (!Object.hasOwn(bucket, key)) bucket[key] = [];
    bucket[key].push(
      compileCondition(condition, this._policy.pathPrefix, this._policy.errorCodePrefix)
    );
    this._emitChange('require', { scope: key });
    return this;
  }

  /**
   * Returns a deep copy of all declared `require()` gates by scope. Useful
   * for inspection and serialization. The copy is fully detached: mutating it
   * can never alter the live gates (a `require()` gate must not be neuterable
   * through an introspection result).
   */
  getRequirements(): IRequirements {
    return structuredClone(this._requirements);
  }

  /**
   * Returns the declared **vocabulary** as a {@link ISetup} object — the inverse
   * of {@link AccessControl#setup}. Member names are returned **unqualified**
   * (`{ admins: ['admin'] }`, not `['admins/admin']`), so the result feeds
   * straight back into `setup()` and round-trips exactly. The reserved `_` key
   * lists ungrouped roles / uncategorized resources.
   *
   * @returns - `{ roles, resources, actions }` — a detached, re-feedable copy.
   *
   * @example
   * ac.setup({ roles: { admins: ['admin'] }, actions: ['publish'] });
   * ac.getVocabulary();
   * // { roles: { admins: ['admin'] }, resources: {}, actions: ['publish'] }
   */
  getVocabulary(): ISetup {
    return {
      roles: this._unqualifyVocab(this._groups),
      resources: this._unqualifyVocab(this._categories),
      actions: [...this._vocabActions]
    };
  }

  /**
   * Strips the `group/` qualifier off each member so a vocabulary store
   * round-trips back through {@link AccessControl#setup} without double-qualifying.
   * @private
   */
  private _unqualifyVocab(store: Record<string, string[]>): Record<string, string[]> {
    const out: Record<string, string[]> = {};
    Object.keys(store).forEach((key: string) => {
      // members under a group/category are stored as `group/member`; strip the
      // qualifier so the result feeds straight back into setup() (the ungrouped
      // `_` bucket holds bare names already).
      const cut = key === GROUP_UNGROUPED ? 0 : key.length + GROUP_SEPARATOR.length;
      out[key] = store[key].map((m: string) => m.slice(cut));
    });
    return out;
  }

  /**
   * Captures the instance's complete, serializable state in one object —
   * grants, `require()` gates and `setup()` vocabulary — the inverse of
   * {@link AccessControl#restore}. Everything is plain JSON (detached deep
   * copies), so a snapshot survives `JSON.stringify` / a `JSONB` column and
   * rebuilds the model exactly.
   *
   * @returns - `{ grants, requirements, vocabulary }`.
   *
   * @example
   * await db.savePolicy(JSON.stringify(ac.snapshot()));
   * // …on boot:
   * const ac2 = new AccessControl().restore(await db.loadPolicy());
   */
  snapshot(): ISnapshot {
    return {
      grants: structuredClone(this._grants),
      requirements: structuredClone(this._requirements),
      vocabulary: this.getVocabulary()
    };
  }

  /**
   * Restores an {@link ISnapshot} onto this instance — the inverse of
   * {@link AccessControl#snapshot} and the one-call way to rebuild a persisted
   * model (grants **and** gates **and** vocabulary).
   *
   * It first {@link AccessControl#reset}s the instance, then re-applies each
   * section through its normal **validated** path (`setGrants()` / `setup()` /
   * `require()`), so the instance ends up **exactly equal** to the snapshot and a
   * restored model is checked just like hand-written setup (reserved/gadget names
   * rejected, charset enforced, conditions recompiled). It is not a raw
   * `Object.assign` of internal state.
   *
   * @param snapshot - A snapshot from {@link AccessControl#snapshot}.
   * @returns - `AccessControl` instance for chaining.
   * @throws {AccessControlError} - If locked, or if any section fails validation.
   *
   * @example
   * // persist everything, rebuild on boot
   * await db.savePolicy(JSON.stringify(ac.snapshot()));
   * const ac = new AccessControl().restore(await db.loadPolicy());
   */
  restore(snapshot: ISnapshot): AccessControl {
    this.reset(); // clears grants, vocabulary and gates (throws if locked)
    this.setGrants(snapshot.grants);
    this.setup(snapshot.vocabulary);
    const req = snapshot.requirements;
    for (const c of req.global) this.require(c);
    for (const cat of Object.keys(req.categories)) {
      for (const c of req.categories[cat]) this.category(cat).require(c);
    }
    for (const res of Object.keys(req.resources)) {
      for (const c of req.resources[res]) this.resource(res).require(c);
    }
    return this;
  }

  /** Lists declared group names (excludes the ungrouped `_` bucket). */
  getGroups(): string[] {
    return Object.keys(this._groups).filter((g: string) => g !== GROUP_UNGROUPED);
  }

  /** Lists declared category names (excludes the uncategorized `_` bucket). */
  getCategories(): string[] {
    return Object.keys(this._categories).filter((c: string) => c !== GROUP_UNGROUPED);
  }

  /**
   * Removes a declared group and its group-level grants node (members stop
   * inheriting the group's grants; their own grants are untouched).
   * @param name - Group name.
   * @returns - `AccessControl` instance for chaining.
   * @throws {AccessControlError} - If locked.
   */
  removeGroup(name: string): AccessControl {
    if (this.isLocked)
      throw new AccessControlError(ERR_LOCK, {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.LOCKED)
      });
    delete this._groups[name];
    if (Object.hasOwn(this._grants, name)) delete this._grants[name];
    this._emitChange('remove', { group: name });
    return this;
  }

  /**
   * Removes a declared category and its category-level grants node across all
   * roles (member resources stop inheriting the category's grants).
   * @param name - Category name.
   * @returns - `AccessControl` instance for chaining.
   * @throws {AccessControlError} - If locked.
   */
  removeCategory(name: string): AccessControl {
    if (this.isLocked)
      throw new AccessControlError(ERR_LOCK, {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.LOCKED)
      });
    delete this._categories[name];
    eachRole(this._grants, (roleInfo: IGrantsItem) => {
      if (Object.hasOwn(roleInfo, name)) delete (roleInfo as UnknownObject)[name];
    });
    this._emitChange('remove', { category: name });
    return this;
  }

  /**
   * Resets the internal grants object and removes all previous grants and
   * declared vocabulary.
   * @returns - `AccessControl` instance for chaining.
   * @throws {AccessControlError} - If called after `.lock()` is called.
   */
  reset(): AccessControl {
    if (this.isLocked)
      throw new AccessControlError(ERR_LOCK, {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.LOCKED)
      });
    this._grants = {};
    this._groups = {};
    this._categories = {};
    this._vocabActions = [];
    this._requirements = { global: [], categories: {}, resources: {} };
    this._emitChange('reset');
    return this;
  }

  /**
   * Freezes the underlying grants model and disables all functionality for
   * modifying it. This is useful when you want to restrict any changes. Any
   * attempts to modify (such as `#setGrants()`, `#reset()`, `#grant()`,
   * `#deny()`, etc) will throw after grants are locked. Note that <b>there
   * is no `unlock()` method</b>. It's like you lock the door and swallow the
   * key. ;)
   *
   * Remember that this does not prevent the `AccessControl` instance from
   * being altered/replaced. Only the grants inner object is locked.
   *
   * <b>A note about performance</b>: This uses recursive `Object.freeze()`.
   * In NodeJS & V8, enumeration performance is not impacted because of this.
   * In fact, it increases the performance because of V8 optimization.
   *
   * @returns {AccessControl} - `AccessControl` instance for chaining.
   *
   * @example
   * ac.grant('admin').create('product');
   * ac.lock(); // called on the AccessControl instance.
   * // or
   * ac.grant('admin').create('product').lock(); // called on the chained Access instance.
   *
   * // After this point, any attempt of modification will throw
   * ac.setGrants({}); // throws
   * ac.grant('user'); // throws..
   * // underlying grants model is not changed
   */
  lock(): AccessControl {
    lockAC(this);
    this._emitChange('lock');
    return this;
  }

  /**
   * Extends the given role(s) with privileges of one or more other roles.
   * @param roles - Role(s) to be extended. Single role as a `String` or
   * multiple roles as an `Array`. Note that if a role does not exist, it will
   * be automatically created.
   * @param extenderRoles - Role(s) to inherit from. Single role as a `String`
   * or multiple roles as an `Array`. Note that if a extender role does not
   * exist, it will throw.
   *
   * @returns - `AccessControl` instance for chaining.
   * @throws {AccessControlError} - If a role is extended by itself or a
   * non-existent role. Or if called after `.lock()` is called.
   */
  extendRole(roles: string | string[], extenderRoles: string | string[]): AccessControl {
    if (this.isLocked)
      throw new AccessControlError(ERR_LOCK, {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.LOCKED)
      });
    extendRole(this._grants, roles, extenderRoles, this._nameOpts());
    this._emitChange('extend', { role: roles, $extend: extenderRoles });
    return this;
  }

  /**
   * Removes all the given role(s) and their granted permissions, at once.
   * @param  roles - An array of roles to be removed. Also accepts a string that
   * can be used to remove a single role.
   *
   * @returns - `AccessControl` instance for chaining.
   * @throws {AccessControlError} - If called after `.lock()` is called.
   */
  removeRoles(roles: string | string[]): AccessControl {
    if (this.isLocked)
      throw new AccessControlError(ERR_LOCK, {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.LOCKED)
      });

    const rolesToRemove: string[] = toStringArray(roles);
    if (rolesToRemove.length === 0 || !isFilledStringArray(rolesToRemove)) {
      throw new AccessControlError(`Invalid role(s).${detail(this._policy.safeErrors, roles)}`, {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.INVALID_NAME)
      });
    }
    rolesToRemove.forEach((roleName: string) => {
      if (!Object.hasOwn(this._grants, roleName)) {
        throw new AccessControlError(
          `Cannot remove a non-existing role.${detail(this._policy.safeErrors, roleName)}`,
          { code: ecode(this._policy.errorCodePrefix, ErrorCode.ROLE_NOT_FOUND), role: roleName }
        );
      }
      delete this._grants[roleName];
    });
    // also remove these roles from $extend list of each remaining role.
    eachRole(this._grants, (roleItem: IGrantsItem, roleName: string) => {
      if (Array.isArray(roleItem.$extend)) {
        roleItem.$extend = subtractArray(roleItem.$extend, rolesToRemove);
      }
    });
    this._emitChange('remove', { roles: rolesToRemove });
    return this;
  }

  /**
   * Removes all the given resources for all roles, at once. Pass the `roles`
   * argument to remove access to resources for those roles only.
   *
   * @param resources - A single or array of resources to be removed.
   * @param [roles] - A single or array of roles to be removed. If omitted,
   * permissions for all roles to all given resources will be removed.
   *
   * @returns - `AccessControl` instance for chaining.
   * @throws {AccessControlError} - If called after `.lock()` is called.
   */
  removeResources(resources: string | string[], roles?: string | string[]): AccessControl {
    if (this.isLocked)
      throw new AccessControlError(ERR_LOCK, {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.LOCKED)
      });

    // _removePermission has a third argument `actionPossession`. if
    // omitted (like below), removes the parent resource object.
    this._removePermission(resources, roles);
    return this;
  }

  /**
   * Gets all the unique roles that have at least one access information.
   *
   * @example
   * ac.grant('admin, user').createAny('video').grant('user').readOwn('profile');
   * console.log(ac.getRoles()); // ["admin", "user"]
   */
  getRoles(): string[] {
    return Object.keys(this._grants);
  }

  /**
   * Gets the list of inherited roles by the given role.
   * @param role - Target role name.
   */
  getInheritedRolesOf(role: string): string[] {
    const roles: string[] = getRoleHierarchyOf(this._grants, role, this._nameOpts());
    roles.shift();
    return roles;
  }

  /**
   * Gets all the unique resources that are granted access for at least one
   * role.
   */
  getResources(): string[] {
    return getResources(this._grants);
  }

  /**
   * Gets the unique action names defined in the grants model. With no argument,
   * returns every action across all roles; with a role (or roles), returns the
   * actions available to that role — including the ones it inherits via
   * `extend()`.
   *
   * @param [role] - Optional role name (or array of role names) to scope to.
   * @returns - The unique action names (a copy).
   * @throws {AccessControlError} - If a given role does not exist.
   *
   * @example
   * ac.grant('user').readOwn('profile').grant('admin').extend('user').deleteAny('post');
   * ac.getActions();        // ["read", "delete"]
   * ac.getActions('user');  // ["read"]
   * ac.getActions('admin'); // ["delete", "read"] (own + inherited)
   */
  getActions(role?: string | string[]): string[] {
    if (role === undefined) return getActions(this._grants);
    const roles = new Set<string>();
    for (const r of toStringArray(role)) {
      roles.add(r);
      for (const inherited of this.getInheritedRolesOf(r)) roles.add(inherited);
    }
    return getActions(this._grants, [...roles]);
  }

  /**
   * Checks whether the grants include the given role or roles.
   * @param role - Role to be checked. You can also pass an array of strings to
   * check multiple roles at once.
   */
  hasRole(role: string | string[]): boolean {
    if (Array.isArray(role)) {
      return role.every((item: string) => Object.hasOwn(this._grants, item));
    }
    return Object.hasOwn(this._grants, role);
  }

  /**
   * Checks whether grants include the given resource or resources.
   * @param resource - Resource to be checked. You can also pass an array of
   * strings to check multiple resources at once.
   */
  hasResource(resource: string | string[]): boolean {
    const resources = this.getResources();
    if (Array.isArray(resource)) {
      return resource.every((item: string) => resources.indexOf(item) >= 0);
    }
    if (typeof resource !== 'string' || resource === '') return false;
    return resources.indexOf(resource) >= 0;
  }

  /**
   * Gets an instance of `Query` object. This is used to check whether the
   * defined access is allowed for the given role(s) and resource. This object
   * provides chainable methods to define and query the access permissions to be
   * checked.
   *
   * @param role - A single role (as a string), a list of roles (as an array) or
   * an `IQueryInfo` object that fully or partially defines the access to be
   * checked.
   * @param [context] - Per-check context data, readable from grant conditions
   * via `$.`. Merged over the constructor's ambient context (per-check
   * wins). Can also be supplied later in the chain via `Query#with()`.
   *
   * @returns - The returned object provides chainable methods to define and
   * query the access permissions to be checked. See `Query` inner class.
   *
   * @example
   * const ac = new AccessControl(grants);
   *
   * ac.can('admin').createAny('profile');
   * // equivalent to:
   * ac.can().role('admin').createAny('profile');
   * // equivalent to:
   * ac.can().role('admin').resource('profile').createAny();
   *
   * // To check for multiple roles:
   * ac.can(['admin', 'user']).createOwn('profile');
   * // Note: when multiple roles checked, acquired attributes are unioned (merged).
   *
   * // With context for conditional grants (two equivalent forms; `.with()`
   * // comes before the action verb, which resolves the Permission):
   * ac.can('manager', { order }).updateAny('order').granted;
   * ac.can('manager').with({ order }).updateAny('order').granted;
   */
  can(role: string | string[] | IQueryInfo, context?: UnknownObject): Query {
    // throw on explicit undefined
    if (arguments.length !== 0 && role === undefined) {
      throw new AccessControlError('Invalid role(s): undefined', {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.INVALID_NAME)
      });
    }
    // other explicit invalid values will be checked in constructor.
    return new Query(this._grants, role, this._resolveOptions(context));
  }

  /**
   * **Fail-closed** counterpart of {@link AccessControl#can}. Identical querying,
   * but a check **never throws**: an invalid query, a `strict` violation
   * (unknown role/action/resource) or a custom/async `{ fn }` condition reached
   * on the sync path all resolve to a denial (`granted:false`, `attributes:[]`)
   * instead of an exception. The `error` event still fires for observability.
   *
   * Prefer this on the request hot path, where a thrown error a caller forgets
   * to catch could otherwise be mishandled into "allow". Keep {@link
   * AccessControl#can} for boot/config validation and tests, where you *want* a
   * typo or misconfiguration to throw loudly.
   *
   * @param role - A single role, a list of roles, or an `IQueryInfo` object.
   * @param [context] - Per-check context data (see {@link AccessControl#can}).
   * @returns - A `Query`; every resulting `Permission` fails closed.
   *
   * @example
   * // throws if 'editor' is an unknown role under strict.roles:
   * if (ac.can('editor').readAny('post').granted) { … }
   * // never throws — an unknown role simply denies:
   * if (ac.tryCan('editor').readAny('post').granted) { … } else denyRequest();
   */
  tryCan(role: string | string[] | IQueryInfo, context?: UnknownObject): Query {
    return new Query(this._grants, role, { ...this._resolveOptions(context), safe: true });
  }

  /**
   * Builds the fully-resolved options threaded into a check: engine policy
   * (path prefix, ownership, strict) plus the merged context (ambient overridden
   * by per-check).
   * @private
   */
  private _resolveOptions(context?: UnknownObject): IResolveOptions {
    return {
      pathPrefix: this._policy.pathPrefix,
      ownerField: this._policy.ownerField,
      owner: this._policy.owner,
      strictChecks: this._policy.strictChecks,
      strictRoles: this._policy.strictRoles,
      strictActions: this._policy.strictActions,
      strictResources: this._policy.strictResources,
      allowRegex: this._policy.allowRegex,
      charset: this._policy.charset,
      safeErrors: this._policy.safeErrors,
      errorCodePrefix: this._policy.errorCodePrefix,
      policyActions: this._policy.actions,
      policyResources: this._policy.resources,
      vocabRoles: this._vocabRoleNames(),
      vocabResources: this._vocabResourceNames(),
      vocabActions: this._vocabActions,
      requirements: this._requirements,
      conditions: this._conditions,
      emitter: this._emitter,
      context: { ...this._context, ...(context ?? {}) }
    };
  }

  /**
   * Resolves a `Permission` for the given query in a single call. This is the
   * one-shot equivalent of the chainable `AccessControl#can()` flow: instead of
   * `.can(<role>).<action>(<resource>)`, you pass a fulfilled `IQueryInfo`
   * object describing the role(s), resource and action (with optional
   * possession via the `:own`/`:any` convention).
   *
   * @param queryInfo - A fulfilled `IQueryInfo` object.
   *
   * @returns - A `Permission` exposing the resolved `granted`, `attributes`,
   * `roles`, `resource` and a `filter()` helper.
   *
   * @example
   * const ac = new AccessControl(grants);
   * const permission = ac.check({
   *   role: 'user',
   *   action: 'update:own',
   *   resource: 'profile'
   * });
   * permission.granted;          // boolean
   * permission.attributes;       // e.g. ['username', 'email', 'address.*']
   * permission.filter(object);   // object with only the allowed attributes
   */
  check(queryInfo: IQueryInfo): Permission {
    return new Permission(this._grants, queryInfo, this._resolveOptions(queryInfo.context));
  }

  /**
   * Async counterpart of {@link AccessControl#check}. Resolves custom/async
   * `{ fn }` conditions (registered via {@link AccessControl#defineCondition}) and
   * returns a fully-resolved `Permission` whose sync `granted`/`attributes`/
   * `filter` accessors are then usable.
   *
   * @param queryInfo - The check query (same shape as `check()`).
   * @returns - A promise of the resolved `Permission`.
   *
   * @example
   * const perm = await ac.checkAsync({ role: 'user', resource: 'doc', action: 'read', context });
   * if (perm.granted) { … }
   */
  async checkAsync(queryInfo: IQueryInfo): Promise<Permission> {
    const perm = new Permission(this._grants, queryInfo, this._resolveOptions(queryInfo.context));
    await perm.grantedAsync; // resolve & memoize so sync accessors work afterwards
    return perm;
  }

  /**
   * Registers a custom condition function, referenced from a grant or
   * `require()` gate as `{ fn: name, args }`. The reference stays
   * JSON-serializable (name + args); the function lives in code. Custom-function
   * conditions are only evaluated on the async path
   * (`grantedAsync`/`checkAsync`); the sync path throws `asyncRequired`.
   *
   * @param name - The condition function name (referenced via `{ fn: name }`).
   * @param fn - `(context, args) => boolean | Promise<boolean>`.
   * @returns - `AccessControl` instance for chaining.
   * @throws {AccessControlError} - If locked, or `name`/`fn` is invalid.
   *
   * @example
   * ac.defineCondition('ipAllowed', async (ctx, args) => isAllowed(ctx.ip, args.cidr));
   * ac.grant('admin').where({ fn: 'ipAllowed', args: { cidr: '10.0.0.0/8' } }).readAny('server');
   */
  defineCondition(name: string, fn: ConditionFunction): AccessControl {
    if (this.isLocked)
      throw new AccessControlError(ERR_LOCK, {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.LOCKED)
      });
    if (typeof name !== 'string' || name.trim() === '') {
      throw new AccessControlError('Invalid condition name, expected a non-empty string.', {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.INVALID_NAME)
      });
    }
    if (typeof fn !== 'function') {
      throw new AccessControlError(
        `Invalid condition function.${detail(this._policy.safeErrors, name)}`,
        {
          code: ecode(this._policy.errorCodePrefix, ErrorCode.INVALID_CONDITION)
        }
      );
    }
    this._conditions[name.trim()] = fn;
    return this;
  }

  // -------------------------------
  // EVENTS
  // -------------------------------

  /**
   * Subscribes a listener to an observational event: `access` (every
   * resolved check — the audit log), `change` (grants/vocabulary mutated) or
   * `error` (a check/op threw). The name accepts the string or the
   * {@link AccessControlEvent} enum. Listeners are **observational only** (they
   * cannot alter a decision) and **isolated** (a throwing listener never breaks
   * a check).
   *
   * @param name - `'access' | 'change' | 'error'` (or the enum).
   * @param listener - Receives the event payload.
   * @returns - `AccessControl` instance for chaining.
   *
   * @example
   * ac.on('access', (e) => audit(e));
   * ac.on(AccessControlEvent.Change, (e) => log(e));
   */
  on(name: AccessControlEventName | AccessControlEvent, listener: EventListener): AccessControl {
    this._emitter.on(name as AccessControlEventName, listener);
    return this;
  }

  /** Subscribes a one-shot listener that auto-removes after the first event. */
  once(name: AccessControlEventName | AccessControlEvent, listener: EventListener): AccessControl {
    this._emitter.once(name as AccessControlEventName, listener);
    return this;
  }

  /**
   * Removes a specific listener, or all listeners for `name` when `listener` is
   * omitted.
   * @returns - `AccessControl` instance for chaining.
   */
  off(name: AccessControlEventName | AccessControlEvent, listener?: EventListener): AccessControl {
    this._emitter.off(name as AccessControlEventName, listener);
    return this;
  }

  /**
   * Emits a `change` event (policy-edit audit). Cheap no-op when there is
   * no `change` listener.
   * @private
   */
  private _emitChange(type: ChangeType, detail?: UnknownObject): void {
    if (!this._emitter.has('change')) return;
    this._emitter.emit('change', { name: 'change', timestamp: Date.now(), type, detail });
  }

  /**
   * Gets an instance of `Grant` (inner) object. This is used to grant access to
   * specified resource(s) for the given role(s).
   *
   * @param [role] A single role (as a string), a list of roles (as an array) or
   * an `IAccessInfo` object that fully or partially defines the access to be
   * granted. This can be omitted and chained with `.role()` to define the role.
   *
   * @returns - The returned object provides chainable properties to build and
   * define the access to be granted. See the examples for details. See `Access`
   * inner class.
   *
   * @throws {AccessControlError} - If `role` is explicitly set to an invalid
   * value.
   * @throws {AccessControlError} - If called after `.lock()` is called.
   *
   * @example
   * const ac = new AccessControl();
   * let attributes = ['*'];
   *
   * ac.grant('admin').createAny('profile', attributes);
   * // equivalent to:
   * ac.grant().role('admin').createAny('profile', attributes);
   * // equivalent to:
   * ac.grant().role('admin').resource('profile').createAny(null, attributes);
   * // equivalent to:
   * ac.grant({
   *     role: 'admin',
   *     resource: 'profile',
   * }).createAny(null, attributes);
   * // equivalent to:
   * ac.grant({
   *     role: 'admin',
   *     resource: 'profile',
   *     action: 'create:any',
   *     attributes: attributes
   * });
   * // equivalent to:
   * ac.grant({
   *     role: 'admin',
   *     resource: 'profile',
   *     action: 'create',
   *     possession: 'any', // omitting this will default to 'any'
   *     attributes: attributes
   * });
   *
   * // To grant same resource and attributes for multiple roles:
   * ac.grant(['admin', 'user']).createOwn('profile', attributes);
   *
   * // Note: when attributes is omitted, it will default to `['*']`
   * // which means all attributes (of the resource) are allowed.
   */
  grant(role?: string | string[] | IAccessInfo): Access {
    if (this.isLocked)
      throw new AccessControlError(ERR_LOCK, {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.LOCKED)
      });
    // throw on explicit undefined
    if (arguments.length !== 0 && role === undefined) {
      throw new AccessControlError('Invalid role(s): undefined', {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.INVALID_NAME)
      });
    }
    // other explicit invalid values will be checked in constructor.
    return new Access(this, role, false);
  }

  /**
   * Gets an instance of `Access` object. This is used to deny access to
   * specified resource(s) for the given role(s). Denying will only remove a
   * previously created grant. So if not granted before, you don't need to deny
   * an access.
   *
   * @param role - A single role (as a string), a list of roles (as an array) or
   * an `IAccessInfo` object that fully or partially defines the access to be
   * denied.
   *
   * @returns - The returned object provides chainable properties to build and
   * define the access to be granted. See `Access` inner class.
   *
   * @throws {AccessControlError} - If `role` is explicitly set to an invalid
   * value.
   * @throws {AccessControlError} - If called after `.lock()` is called.
   *
   * @example
   * const ac = new AccessControl();
   *
   * ac.deny('admin').createAny('profile');
   * // equivalent to:
   * ac.deny().role('admin').createAny('profile');
   * // equivalent to:
   * ac.deny().role('admin').resource('profile').createAny();
   * // equivalent to:
   * ac.deny({
   *     role: 'admin',
   *     resource: 'profile',
   * }).createAny();
   * // equivalent to:
   * ac.deny({
   *     role: 'admin',
   *     resource: 'profile',
   *     action: 'create:any'
   * });
   * // equivalent to:
   * ac.deny({
   *     role: 'admin',
   *     resource: 'profile',
   *     action: 'create',
   *     possession: 'any' // omitting this will default to 'any'
   * });
   *
   * // To deny same resource for multiple roles:
   * ac.deny(['admin', 'user']).createOwn('profile');
   */
  deny(role?: string | string[] | IAccessInfo): Access {
    if (this.isLocked)
      throw new AccessControlError(ERR_LOCK, {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.LOCKED)
      });
    // throw on explicit undefined
    if (arguments.length !== 0 && role === undefined) {
      throw new AccessControlError('Invalid role(s): undefined', {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.INVALID_NAME)
      });
    }
    // other explicit invalid values will be checked in constructor.
    return new Access(this, role, true);
  }

  // -------------------------------
  //  PRIVATE METHODS
  // -------------------------------

  /**
   * @private
   */
  _removePermission(resources: string | string[], roles?: string | string[]) {
    const safe = this._policy.safeErrors;
    resources = toStringArray(resources);
    // resources is set but returns empty array.
    if (resources.length === 0 || !isFilledStringArray(resources)) {
      throw new AccessControlError(`Invalid resource(s).${detail(safe, resources)}`, {
        code: ecode(this._policy.errorCodePrefix, ErrorCode.INVALID_NAME)
      });
    }

    if (roles !== undefined) {
      roles = toStringArray(roles);
      // roles is set but returns empty array.
      if (roles.length === 0 || !isFilledStringArray(roles)) {
        throw new AccessControlError(`Invalid role(s).${detail(safe, roles)}`, {
          code: ecode(this._policy.errorCodePrefix, ErrorCode.INVALID_NAME)
        });
      }
    }
    eachRoleResource(this._grants, (role: string, resource: string) => {
      // roles is optional: remove for all roles, or only those listed.
      if (resources.indexOf(resource) >= 0 && (!roles || roles.indexOf(role) >= 0)) {
        delete this._grants[role][resource];
      }
    });
  }

  // -------------------------------
  //  PUBLIC STATIC METHODS
  // -------------------------------

  /**
   * A utility method for deep cloning the given data object(s) while filtering
   * its properties by the given attribute (glob) notations. Includes all
   * matched properties and removes the rest.
   *
   * Note that this should be used to manipulate data / arbitrary objects with
   * enumerable properties. It will not deal with preserving the prototype-chain
   * of the given object.
   *
   * @param data - A single or array of data objects to be filtered.
   * @param attributes - The attribute glob notation(s) to be processed. You can
   * use wildcard stars (*) and negate the notation by prepending a bang (!). A
   * negated notation will be excluded. Order of the globs do not matter, they
   * will be logically sorted. Loose globs will be processed first and verbose
   * globs or normal notations will be processed last. e.g. `[ "car.model", "*",
   * "!car.*" ]` will be sorted as: `[ "*", "!car.*", "car.model" ]`. Passing no
   * parameters or passing an empty string (`""` or `[""]`) will empty the
   * source object.
   *
   * @returns - Returns the filtered data object or array of data objects.
   *
   * @example
   * var assets = { notebook: "Mac", car: { brand: "Ford", model: "Mustang", year: 1970, color: "red" } };
   *
   * var filtered = AccessControl.filter(assets, [ "*", "!car.*", "car.model" ]);
   * console.log(assets); // { notebook: "Mac", car: { model: "Mustang" } }
   *
   * filtered = AccessControl.filter(assets, "*"); // or AccessControl.filter(assets, ["*"]);
   * console.log(assets); // { notebook: "Mac", car: { model: "Mustang" } }
   *
   * filtered = AccessControl.filter(assets); // or AccessControl.filter(assets, "");
   * console.log(assets); // {}
   */
  static filter(
    data: UnknownObject | UnknownObject[],
    attributes: string[]
  ): UnknownObject | UnknownObject[] {
    return filterAll(data, attributes);
  }

  /**
   * Checks whether the given object is an instance of `AccessControlError`.
   * @param object - Object to be checked.
   */
  static isACError(object: unknown): boolean {
    return object instanceof AccessControlError;
  }
}
