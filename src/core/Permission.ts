// own modules
import { AccessControlError } from '../core/index.js';
import { ErrorCode } from '../enums/index.js';
import type {
  AccessReason,
  IGrants,
  IQueryInfo,
  IResolveOptions,
  UnknownObject
} from '../types/index.js';
import {
  ecode,
  filterAll,
  GROUP_SEPARATOR,
  resolveAccess,
  resolveAccessAsync,
  toStringArray
} from '../utils/index.js';

/**
 * Represents the resolved `Permission` for a query — the granted (or denied)
 * access for the target role(s) and resource. Obtain one in two ways:
 *
 * 1. The chainable form via `AccessControl#can()`, which returns a `Permission`
 *    once an action method such as `.createAny()` is called:
 *    ```js
 *    const permission = ac.can('user').createAny('video');
 *    console.log(permission.granted); // boolean
 *    ```
 * 2. The one-shot form via `AccessControl#check()`, passing a fulfilled
 *    `IQueryInfo` object:
 *    ```js
 *    const permission = ac.check({
 *      role: 'user',
 *      resource: 'video',
 *      action: 'create:any'
 *    });
 *    console.log(permission.granted); // boolean
 *    ```
 *
 */
export class Permission {
  /**
   * @private
   */
  private _: {
    roles: string[];
    resource: string;
    /** Bare action name (any `:possession` suffix stripped). */
    action: string;
    /** Possession: the requested one until resolution overwrites it with the effective one. */
    possession: 'own' | 'any';
    /** Resolved attributes; `undefined` while a `{ fn }` check awaits the async path. */
    attributes?: string[];
  };

  /** Denial reason for the resolved attributes; set on resolution. */
  private _reason?: AccessReason;

  /** Retained for the async resolution path. */
  private readonly _grants: IGrants;
  private readonly _query: IQueryInfo;
  private readonly _options?: IResolveOptions;

  /**
   * Initializes a new `Permission` instance.
   * @private
   *
   * @param grants - The underlying grants model.
   * @param query - An `IQueryInfo` arbitrary object.
   * @param [options] - `pathPrefix`, the merged check `context`, ownership,
   * strict, vocabulary, require() gates and condition registry.
   */
  constructor(grants: IGrants, query: IQueryInfo, options?: IResolveOptions) {
    this._grants = grants;
    this._query = query;
    this._options = options;
    const action = String(query.action ?? '');
    this._ = {
      roles: toStringArray(query.role),
      resource: query.resource ?? '',
      action: action.split(':')[0],
      possession:
        (query.possession as 'own' | 'any' | undefined) ??
        (action.split(':')[1] as 'own' | 'any' | undefined) ??
        'any'
    };
    // Resolve eagerly so validation/strict errors surface at the call site, as
    // before — except a custom/async `{ fn }` condition, which defers to the
    // async path instead of throwing at construction.
    try {
      const res = resolveAccess(grants, query, options);
      this._.attributes = res.attributes;
      this._.possession = res.possession;
      this._reason = res.reason;
      this._emitAccess();
    } catch (err) {
      if (err instanceof AccessControlError && err.asyncRequired) {
        // leave attributes undefined → resolve via the async path.
      } else {
        this._emitError(err);
        // fail-closed mode (tryCan): swallow the fault and deny.
        if (!this._options?.safe) throw err;
        this._.attributes = [];
      }
    }
  }

  /**
   * Specifies the roles for which the permission is queried for.
   * Even if the permission is queried for a single role, this will still
   * return an array.
   *
   * If the returned array has multiple roles, this does not necessarily mean
   * that the queried permission is granted or denied for each and all roles.
   * Note that when a permission is queried for multiple roles, attributes
   * are unioned (merged) for all given roles. This means "at least one of
   * these roles" have the permission for this action and resource attribute.
   */
  get roles(): string[] {
    // frozen copy so callers cannot mutate the internal state
    return Object.freeze(this._.roles.concat()) as string[];
  }

  /**
   * Specifies the target resource for which the permission is queried for.
   */
  get resource(): string {
    return this._.resource;
  }

  /**
   * The action the permission was checked for — the bare verb, with any
   * `:possession` suffix stripped (e.g. `read` for `read:any`, `publish` for a
   * custom `publish:own`).
   */
  get action(): string {
    return this._.action;
  }

  /**
   * The possession that **effectively** granted access — `'own'` or `'any'`.
   * Because `any` ⊇ `own`, a query for `own` that matched via an `any` grant
   * resolves to `'any'`. On denial, the requested possession is echoed back.
   *
   * @throws {AccessControlError} - If an applicable rule/gate has a custom/async
   * `{ fn }` condition; use {@link Permission#grantedAsync} first.
   */
  get possession(): 'own' | 'any' {
    this._resolvedSync();
    return this._.possession;
  }

  /**
   * Gets an array of allowed attributes which are defined via
   * Glob notation. If access is not granted, this will be an empty array.
   *
   * Note that when a permission is queried for multiple roles, attributes
   * are unioned (merged) for all given roles. This means "at least one of
   * these roles" have the permission for this action and resource attribute.
   */
  get attributes(): string[] {
    // frozen copy so callers cannot mutate the internal state
    return Object.freeze(this._resolvedSync().concat()) as string[];
  }

  /**
   * Specifies whether the permission is granted. If `true`, this means at
   * least one attribute of the target resource is allowed.
   *
   * @throws {AccessControlError} - If an applicable rule/gate has a custom/async
   * `{ fn }` condition; use {@link Permission#grantedAsync} instead.
   */
  get granted(): boolean {
    return Permission._hasGrant(this._resolvedSync());
  }

  /**
   * Async counterpart of {@link Permission#granted}. Resolves custom/async
   * `{ fn }` conditions (and works for fully-declarative checks too). After it
   * resolves, the sync `attributes`/`granted`/`filter` accessors are usable.
   *
   * @example
   * if (await ac.can('user', ctx).readAny('post').grantedAsync) { … }
   */
  get grantedAsync(): Promise<boolean> {
    return this._resolveAsync().then((attrs) => Permission._hasGrant(attrs));
  }

  /**
   * Filters the given data object (or array of objects) by the permission
   * attributes and returns this data with allowed attributes.
   * @param data - Data object to be filtered. Either a single object or array
   * of objects.
   * @returns - The filtered data object.
   */
  filter(data: UnknownObject | UnknownObject[]): UnknownObject | UnknownObject[] {
    return filterAll(data, this.attributes);
  }

  /** Whether an attribute set grants access (≥1 non-negated attribute). */
  private static _hasGrant(attributes: string[]): boolean {
    return attributes.length > 0 && attributes.some((attr) => attr.trim().slice(0, 1) !== '!');
  }

  /**
   * Returns the synchronously-resolved attributes; throws `asyncRequired` if a
   * `{ fn }` condition deferred resolution and it hasn't been awaited yet.
   * @private
   */
  private _resolvedSync(): string[] {
    if (this._.attributes !== undefined) return this._.attributes;
    // fail-closed mode (tryCan): a custom/async condition denies on the sync path
    // (use grantedAsync to actually evaluate it) rather than throwing.
    if (this._options?.safe) return [];
    throw new AccessControlError(
      'This permission has a custom/async condition; use grantedAsync()/checkAsync().',
      { asyncRequired: true, code: ecode(this._options?.errorCodePrefix, ErrorCode.ASYNC_REQUIRED) }
    );
  }

  /**
   * Resolves attributes via the async path (awaiting `{ fn }` conditions) and
   * memoizes them so subsequent sync accessors work.
   * @private
   */
  private async _resolveAsync(): Promise<string[]> {
    if (this._.attributes === undefined) {
      try {
        const res = await resolveAccessAsync(this._grants, this._query, this._options);
        this._.attributes = res.attributes;
        this._.possession = res.possession;
        this._reason = res.reason;
        this._emitAccess();
      } catch (err) {
        this._emitError(err);
        // fail-closed mode (tryCan): swallow the fault and deny.
        if (!this._options?.safe) throw err;
        this._.attributes = [];
      }
    }
    return this._.attributes;
  }

  /** Emits the `access` audit event (once per resolution), if a listener exists. */
  private _emitAccess(): void {
    const emitter = this._options?.emitter;
    if (!emitter?.has('access')) return;
    /* istanbul ignore next -- defensive: attributes/action are always set when access emits */
    const attrs = this._.attributes ?? [];
    /* istanbul ignore next -- defensive: action is always present when access emits */
    const parts = String(this._query.action ?? '').split(':');
    const possession =
      (this._query.possession as 'own' | 'any' | undefined) ??
      (parts[1] as 'own' | 'any' | undefined);
    emitter.emit('access', {
      name: 'access',
      timestamp: Date.now(),
      roles: this._.roles,
      resource: this._.resource,
      category: this._.resource.includes(GROUP_SEPARATOR)
        ? this._.resource.split(GROUP_SEPARATOR)[0]
        : undefined,
      action: parts[0],
      possession,
      granted: Permission._hasGrant(attrs),
      attributes: attrs,
      reason: this._reason,
      context: this._options?.context
    });
  }

  /** Emits the `error` event when a check throws. */
  private _emitError(err: unknown): void {
    const emitter = this._options?.emitter;
    if (!emitter?.has('error')) return;
    const parts = String(this._query.action ?? '').split(':');
    emitter.emit('error', {
      name: 'error',
      timestamp: Date.now(),
      error:
        err instanceof AccessControlError
          ? err
          : new AccessControlError(err instanceof Error ? err.message : String(err)),
      operation: 'check',
      roles: this._.roles,
      resource: this._.resource,
      action: parts[0]
    });
  }
}
