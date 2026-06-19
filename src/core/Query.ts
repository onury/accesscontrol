import { AccessControlError, Permission } from '../core/index.js';
import { Action, ErrorCode, Possession } from '../enums/index.js';
import type { IGrants, IQueryInfo, IResolveOptions, UnknownObject } from '../types/index.js';
import { ecode, type } from '../utils/index.js';

/**
 * Represents the inner `Query` class that helps build an access information
 * for querying and checking permissions, from the underlying grants model.
 * You can get a first instance of this class by calling
 * `AccessControl#can(<role>)` method.
 */
export class Query {
  /**
   * Inner `IQueryInfo` object.
   */
  protected _: IQueryInfo = {};

  /**
   * Main grants object.
   */
  protected _grants: IGrants;

  /** Merged check context (ambient + per-check), readable from conditions. */
  protected _ctx: UnknownObject = {};

  /** Resolved engine options (path prefix, ownership, strict) for the check. */
  protected _resolve: IResolveOptions = {};

  /** Fail-closed mode (from `tryCan`): suppress throws, resolve to denial. */
  protected _safe = false;

  /**
   * Initializes a new instance of `Query`.
   * @private
   *
   * @param grants - Underlying grants model against which the permissions will
   * be queried and checked.
   * @param [roleOrInfo] - Either a single or array of roles or an `IQueryInfo`
   * arbitrary object.
   * @param [options] - Resolved engine options + the ambient/per-check `context`
   * carried from the `AccessControl` instance.
   */
  constructor(
    grants: IGrants,
    roleOrInfo?: string | string[] | IQueryInfo,
    options?: IResolveOptions
  ) {
    this._grants = grants;
    this._resolve = options ?? {};
    this._ctx = { ...(options?.context ?? {}) };
    this._safe = options?.safe === true;

    if (typeof roleOrInfo === 'string' || Array.isArray(roleOrInfo)) {
      // if this is just role(s); a string or array; we start building
      // the grant object for this.
      this.role(roleOrInfo);
    } else if (type(roleOrInfo) === 'object') {
      // if this is a (permission) object, we directly build attributes
      // from grants.
      if (Object.keys(roleOrInfo as IQueryInfo).length === 0) {
        // fail-closed mode defers to the (denying) Permission instead of throwing
        if (!this._safe)
          throw new AccessControlError('Invalid IQueryInfo: {}', {
            code: ecode(this._resolve.errorCodePrefix, ErrorCode.INVALID_QUERY)
          });
      } else {
        this._ = roleOrInfo as IQueryInfo;
        // a context carried on the query object merges in (per-check wins).
        /* istanbul ignore next -- both arms exercised; istanbul mis-maps the guard */
        if (this._.context) this._ctx = { ...this._ctx, ...this._.context };
      }
    } else if (roleOrInfo !== undefined && !this._safe) {
      // undefined is allowed (`role` can be omitted) but throw if some
      // other type is passed (fail-closed mode defers to the denying Permission).
      throw new AccessControlError(
        'Invalid role(s), expected a valid string, string[] or IQueryInfo.',
        { code: ecode(this._resolve.errorCodePrefix, ErrorCode.INVALID_NAME) }
      );
    }
  }

  /**
   * Supplies per-check context data, readable from grant conditions via `$.`.
   * Merges over any ambient/earlier context (later wins). The fluent
   * equivalent of passing context as the 2nd argument of `AccessControl#can()`.
   * @param context - The context data bag for this check.
   * @returns - Self instance of `Query`.
   */
  with(context: UnknownObject): Query {
    this._ctx = { ...this._ctx, ...context };
    return this;
  }

  // -------------------------------
  //  PUBLIC METHODS
  // -------------------------------

  /**
   * A chainer method that sets the role(s) for this `Query` instance.
   * @param role - A single or array of roles.
   * @returns - Self instance of `Query`.
   */
  role(role: string | string[]): Query {
    this._.role = role;
    return this;
  }

  /**
   * A chainer method that sets the resource for this `Query` instance.
   * @param resource - Target resource for this `Query` instance.
   * @returns - Self instance of `Query`.
   */
  resource(resource: string): Query {
    this._.resource = resource;
    return this;
  }

  /**
   * Generic check entry for **any** action — CRUD or custom. The CRUD query
   * methods are named sugar over this. `actionSpec` may carry possession via the
   * `:own`/`:any` convention (omit ⇒ `any`).
   * @param actionSpec - Action name, optionally `name:own`/`name:any`.
   * @param [resource] - Target resource.
   * @returns - The resolved `Permission`.
   *
   * @example
   * ac.can('author', { user, article }).action('publish:own', 'article').granted;
   */
  action(actionSpec: string, resource?: string): Permission {
    const [action, poss] = String(actionSpec).split(':');
    const possession = (poss ?? Possession.ANY) as Possession;
    return this._getPermission(action as Action, possession, resource);
  }

  /**
   * The single sanctioned alias of {@link Query#action}. Generic: CRUD and
   * custom. e.g. `ac.can('admin').do('update')` / `.do('publish', 'article')`.
   * @param actionSpec - Action name, optionally `name:own`/`name:any`.
   * @param [resource] - Target resource.
   * @returns - The resolved `Permission`.
   */
  do(actionSpec: string, resource?: string): Permission {
    return this.action(actionSpec, resource);
  }

  /**
   * Queries the underlying grant model and checks whether the current role(s)
   * can "create" their "own" resource.
   *
   * @param [resource] - Defines the target resource to be checked. This is only
   * optional if the target resource is previously defined. If not defined and
   * omitted, this will throw.
   *
   * @throws {Error} - If the access query instance to be committed has any
   * invalid data.
   *
   * @returns - An object that defines whether the permission is granted; and
   * the resource attributes that the permission is granted for.
   */
  createOwn(resource?: string): Permission {
    return this._getPermission(Action.CREATE, Possession.OWN, resource);
  }

  /**
   * Queries the underlying grant model and checks whether the current role(s)
   * can "create" "any" resource.
   *
   * @param [resource] - Defines the target resource to be checked. This is only
   * optional if the target resource is previously defined. If not defined and
   * omitted, this will throw.
   *
   * @throws {Error} - If the access query instance to be committed has any
   * invalid data.
   *
   * @returns - An object that defines whether the permission is granted; and
   * the resource attributes that the permission is granted for.
   */
  createAny(resource?: string): Permission {
    return this._getPermission(Action.CREATE, Possession.ANY, resource);
  }
  /**
   * Alias if `createAny`
   * @private
   */
  create(resource?: string): Permission {
    return this.createAny(resource);
  }

  /**
   * Queries the underlying grant model and checks whether the current role(s)
   * can "read" their "own" resource.
   *
   * @param [resource] - Defines the target resource to be checked. This is only
   * optional if the target resource is previously defined. If not defined and
   * omitted, this will throw.
   *
   * @throws {Error} - If the access query instance to be committed has any
   * invalid data.
   *
   * @returns - An object that defines whether the permission is granted; and
   * the resource attributes that the permission is granted for.
   */
  readOwn(resource?: string): Permission {
    return this._getPermission(Action.READ, Possession.OWN, resource);
  }

  /**
   * Queries the underlying grant model and checks whether the current role(s)
   * can "read" "any" resource.
   *
   * @param [resource] - Defines the target resource to be checked. This is only
   * optional if the target resource is previously defined. If not defined and
   * omitted, this will throw.
   *
   * @throws {Error} - If the access query instance to be committed has any
   * invalid data.
   *
   * @returns - An object that defines whether the permission is granted; and
   * the resource attributes that the permission is granted for.
   */
  readAny(resource?: string): Permission {
    return this._getPermission(Action.READ, Possession.ANY, resource);
  }
  /**
   * Alias if `readAny`
   * @private
   */
  read(resource?: string): Permission {
    return this.readAny(resource);
  }

  /**
   * Queries the underlying grant model and checks whether the current role(s)
   * can "update" their "own" resource.
   *
   * @param [resource] - Defines the target resource to be checked. This is only
   * optional if the target resource is previously defined. If not defined and
   * omitted, this will throw.
   *
   * @throws {Error} - If the access query instance to be committed has any
   * invalid data.
   *
   * @returns - An object that defines whether the permission is granted; and
   * the resource attributes that the permission is granted for.
   */
  updateOwn(resource?: string): Permission {
    return this._getPermission(Action.UPDATE, Possession.OWN, resource);
  }

  /**
   * Queries the underlying grant model and checks whether the current role(s)
   * can "update" "any" resource.
   *
   * @param [resource] - Defines the target resource to be checked. This is only
   * optional if the target resource is previously defined. If not defined and
   * omitted, this will throw.
   *
   * @throws {Error} - If the access query instance to be committed has any
   * invalid data.
   *
   * @returns - An object that defines whether the permission is granted; and
   * the resource attributes that the permission is granted for.
   */
  updateAny(resource?: string): Permission {
    return this._getPermission(Action.UPDATE, Possession.ANY, resource);
  }
  /**
   * Alias if `updateAny`
   * @private
   */
  update(resource?: string): Permission {
    return this.updateAny(resource);
  }

  /**
   * Queries the underlying grant model and checks whether the current role(s)
   * can "delete" their "own" resource.
   *
   * @param [resource] - Defines the target resource to be checked. This is only
   * optional if the target resource is previously defined. If not defined and
   * omitted, this will throw.
   *
   * @throws {Error} - If the access query instance to be committed has any
   * invalid data.
   *
   * @returns - An object that defines whether the permission is granted; and
   * the resource attributes that the permission is granted for.
   */
  deleteOwn(resource?: string): Permission {
    return this._getPermission(Action.DELETE, Possession.OWN, resource);
  }

  /**
   * Queries the underlying grant model and checks whether the current role(s)
   * can "delete" "any" resource.
   *
   * @param [resource] - Defines the target resource to be checked. This is only
   * optional if the target resource is previously defined. If not defined and
   * omitted, this will throw.
   *
   * @throws {Error} - If the access query instance to be committed has any
   * invalid data.
   *
   * @returns - An object that defines whether the permission is granted; and
   * the resource attributes that the permission is granted for.
   */
  deleteAny(resource?: string): Permission {
    return this._getPermission(Action.DELETE, Possession.ANY, resource);
  }
  /**
   * Alias if `deleteAny`
   * @private
   */
  delete(resource?: string): Permission {
    return this.deleteAny(resource);
  }

  // -------------------------------
  //  PRIVATE METHODS
  // -------------------------------

  /**
   * @private
   * @param {String} action
   * @param {String} possession
   * @param {String} [resource]
   * @returns {Permission}
   */
  private _getPermission(
    action: Action | string,
    possession: Possession,
    resource?: string
  ): Permission {
    this._.action = action;
    this._.possession = possession;
    if (resource) this._.resource = resource;
    return new Permission(this._grants, this._, {
      ...this._resolve,
      context: this._ctx
    });
  }
}
