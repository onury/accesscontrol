import { AccessControlError } from '../core/index.js';
import { Action, ErrorCode, Possession } from '../enums/index.js';
import type { AccessControl } from '../index.js';
import type { ConditionJSON, ConditionLeaf, IAccessInfo, IGrants } from '../types/index.js';
import {
  commitToGrants,
  ecode,
  extendRole,
  hasValidNames,
  type INameOptions,
  isInfoFulfilled,
  lockAC,
  preCreateRoles,
  resetAttributes,
  toStringArray,
  type
} from '../utils/index.js';

/**
 * Represents the inner `Access` class that helps build an access information
 * to be granted or denied; and finally commits it to the underlying grants
 * model. You can get a first instance of this class by calling
 * `AccessControl#grant()` or `AccessControl#deny()` methods.
 */
export class Access {
  /** Inner `IAccessInfo` object. */
  protected _: IAccessInfo = {};

  /**
   * Pending `.during()` expressions. Kept separate from `_.condition` and
   * merged at commit so a later `.where()` (which overwrites the condition by
   * contract) can never silently drop an attached schedule.
   */
  protected _during: string[] = [];

  /** Main grants object. */
  protected _ac: AccessControl;

  /** Main grants object. */
  protected _grants: IGrants;

  /** Notation path sentinel for compiling conditions (from the engine policy). */
  protected _pathPrefix: string;

  /** Charset / safe-errors policy threaded into name validation + messages. */
  protected _nameOpts: INameOptions;

  /**
   * Initializes a new instance of `Access`.
   * @private
   *
   * @param ac - AccessControl instance.
   * @param [roleOrInfo] - Either an `IAccessInfo` object, a single or an array
   * of roles. If an object is passed, possession and attributes properties are
   * optional. CAUTION: if attributes is omitted, and access is not denied, it
   * will default to `["*"]` which means "all attributes allowed". If
   * possession is omitted, it will default to `"any"`.
   * @param denied - Specifies whether this `Access` is denied.
   */
  constructor(
    ac: AccessControl,
    roleOrInfo?: string | string[] | IAccessInfo,
    denied: boolean = false
  ) {
    this._ac = ac;
    this._grants = (ac as any)._grants;
    this._pathPrefix = (ac as any)._policy?.pathPrefix ?? '$';
    this._nameOpts = (ac as any)._nameOpts ? (ac as any)._nameOpts() : {};
    this._.denied = denied;

    if (typeof roleOrInfo === 'string' || Array.isArray(roleOrInfo)) {
      this.role(roleOrInfo);
    } else if (type(roleOrInfo) === 'object') {
      if (Object.keys(roleOrInfo as IAccessInfo).length === 0) {
        throw new AccessControlError('Invalid IAccessInfo: {}', {
          code: ecode(this._nameOpts.errorCodePrefix, ErrorCode.INVALID_GRANT)
        });
      }
      // if an IAccessInfo instance is passed and it has 'action' defined, we
      // should directly commit it to grants.
      (roleOrInfo as IAccessInfo).denied = denied;
      this._ = resetAttributes(roleOrInfo as IAccessInfo);
      if (isInfoFulfilled(this._)) {
        commitToGrants(this._grants, this._, true, this._pathPrefix, this._nameOpts);
        (this._ac as any)._emitChange(this._.denied ? 'deny' : 'grant', {
          role: this._.role,
          resource: this._.resource,
          action: this._.action
        });
      }
    } else if (roleOrInfo !== undefined) {
      // undefined is allowed (`roleOrInfo` can be omitted) but throw if
      // some other type is passed.
      throw new AccessControlError(
        'Invalid role(s), expected a valid string, string[] or IAccessInfo.',
        { code: ecode(this._nameOpts.errorCodePrefix, ErrorCode.INVALID_NAME) }
      );
    }
  }

  // -------------------------------
  //  PUBLIC PROPERTIES
  // -------------------------------

  /**
   * Specifies whether this access is initially denied.
   */
  get denied(): boolean {
    return Boolean(this._.denied);
  }

  // -------------------------------
  //  PUBLIC METHODS
  // -------------------------------

  /**
   * A chainer method that sets the role(s) for this `Access` instance.
   * @param value - A single or array of roles.
   * @returns - Self instance of `Access`.
   */
  role(value: string | string[]): Access {
    // in case chain is not terminated (e.g. `ac.grant('user')`) we'll
    // create/commit the roles to grants with an empty object.
    preCreateRoles(this._grants, value, this._nameOpts);

    this._.role = value;
    return this;
  }

  /**
   * A chainer method that sets the resource for this `Access` instance.
   * @param value - Target resource for this `Access` instance.
   * @returns - Self instance of `Access`.
   */
  resource(value: string | string[]): Access {
    // this will throw if any item fails (qualified category/resource allowed)
    hasValidNames(value, true, true, this._nameOpts);
    this._.resource = value;
    return this;
  }

  /**
   * Sets the array of allowed attributes for this `Access` instance.
   * @param value - Attributes to be set.
   * @returns - Self instance of `Access`.
   */
  attributes(value: string | string[]): Access {
    this._.attributes = value;
    return this;
  }

  /**
   * Attaches a declarative condition to this grant — *whether* the grant
   * applies at check time. Accepts the string-sugar form
   * (`'$.order.value > 100000'`) or canonical JSON (`{ and|or|not }` /
   * `[lhs, op, rhs]`); it is compiled and validated when committed. Pairs with
   * the attribute list (`['*','!password']`), which decides *what fields* return.
   * @param condition - The condition (string sugar or canonical JSON).
   * @returns - Self instance of `Access`.
   *
   * @example
   * ac.grant('manager')
   *   .where('$.order.value > 100000')
   *   .updateAny('order', ['*']);
   */
  where(condition: ConditionJSON): Access {
    this._.condition = condition;
    return this;
  }

  /**
   * Attaches a temporal schedule to this grant: it applies only while the
   * check instant — the reserved `$.now` (i.e. `context.now`, defaulting to
   * the current time) — is covered by the given
   * {@link https://dtrexp.org | dtrexp} expression. Shorthand for AND-ing
   * `['$.now', 'during', expression]` into this grant's condition; composes
   * with `.where()` regardless of call order. The timezone comes from the
   * reserved `context.tz` (IANA name; defaults to the system zone). The
   * expression is validated when the chain commits (on the action call):
   * malformed or never-matching expressions throw.
   *
   * Repeated calls AND together (all schedules must cover the instant); to
   * express alternatives, use a union (`|`) inside a single expression.
   * @param expression - A dtrexp date-time range / recurrence expression.
   * @returns - Self instance of `Access`.
   *
   * @example
   * ac.grant('trader')
   *   .where('$.order.value <= 100000')
   *   .during('T0900:1800 E1:5') // Mon–Fri, 09:00–18:00
   *   .updateAny('order', ['*']);
   */
  during(expression: string): Access {
    this._during.push(expression);
    return this;
  }

  /**
   * Sets the roles to be extended (inherited) for this `Access` instance.
   *
   * @param roles - A single or array of roles.
   * @returns - Self instance of `Access`.
   *
   * @example
   * ac.grant('user').createAny('video')
   *   .grant('admin').extend('user');
   * const permission = ac.can('admin').createAny('video');
   * console.log(permission.granted); // true
   */
  extend(roles: string | string[]): Access {
    extendRole(this._grants, this._.role as string, roles, this._nameOpts);
    return this;
  }

  /**
   * Shorthand to switch to a new `Access` instance with a different role
   * within the method chain.
   * @param [roleOrInfo] - Either a single or an array of roles or an
   * @returns - A new `Access` instance.
   * @example
   * ac.grant('user').createOwn('video')
   *   .grant('admin').updateAny('video');
   */
  grant(roleOrInfo?: string | string[] | IAccessInfo): Access {
    return new Access(this._ac, roleOrInfo, false).attributes(['*']);
  }

  /**
   * Shorthand to switch to a new `Access` instance with a different
   * (or same) role within the method chain.
   * @param [roleOrInfo] - Either a single or an array of roles or an
   * @returns - A new `Access` instance.
   * @example
   * ac.grant('admin').createAny('video')
   *   .deny('user').deleteAny('video');
   */
  deny(roleOrInfo?: string | string[] | IAccessInfo): Access {
    return new Access(this._ac, roleOrInfo, true).attributes([]);
  }

  /**
   * Chainable, convenience shortcut for `AccessControl#lock()`.
   */
  lock(): Access {
    lockAC(this._ac);
    return this;
  }

  /**
   * Generic authoring entry for **any** action — CRUD or custom. The CRUD
   * methods (`createAny`, `updateOwn`, …) are named sugar over this same commit
   * path. `actionSpec` may carry possession via the `:own`/`:any` convention
   * (omit ⇒ `any`).
   * @param actionSpec - Action name, optionally `name:own`/`name:any`.
   * @param [resource] - Target resource(s).
   * @param [attributes] - Granted attributes (defaults per grant/deny).
   * @returns - Self instance of `Access`.
   *
   * @example
   * ac.grant('editor').action('publish', 'article', ['*']);      // publish:any
   * ac.grant('author').action('publish:own', 'article', ['*']);  // ownership-gated
   */
  action(actionSpec: string, resource?: string | string[], attributes?: string | string[]): Access {
    const [action, poss] = String(actionSpec).split(':');
    const possession = (poss ?? Possession.ANY) as Possession;
    return this._prepareAndCommit(action as Action, possession, resource, attributes);
  }

  /**
   * The single sanctioned alias of {@link Access#action} — the one
   * intentional exception to the v3 alias purge. Generic: CRUD and custom.
   * @param actionSpec - Action name, optionally `name:own`/`name:any`.
   * @param [resource] - Target resource(s).
   * @param [attributes] - Granted attributes.
   * @returns - Self instance of `Access`.
   */
  do(actionSpec: string, resource?: string | string[], attributes?: string | string[]): Access {
    return this.action(actionSpec, resource, attributes);
  }

  /**
   * Sets the action to `"create"` and possession to `"own"` and commits the
   * current access instance to the underlying grant model.
   *
   * @param [resource] - Defines the target resource this access is granted or
   * denied for. This is only optional if the resource is previously defined.
   * If not defined and omitted, this will throw.
   * @param [attributes] - Defines the resource attributes for which the access
   * is granted for. If access is denied previously by calling `.deny()`
   * thiswill default to an empty array (which means no attributes allowed).
   * Otherwise (if granted before via `.grant()`) this will default to `["*"]`
   * (which means all attributes allowed.)
   *
   * @throws {AccessControlError} - If the access instance to be committed has
   * any invalid data.
   *
   * @returns - Self instance of `Access` so that you can chain and define
   * another access instance to be committed.
   */
  createOwn(resource?: string | string[], attributes?: string | string[]): Access {
    return this._prepareAndCommit(Action.CREATE, Possession.OWN, resource, attributes);
  }

  /**
   * Sets the action to `"create"` and possession to `"any"` and commits the
   * current access instance to the underlying grant model.
   *
   * @param [resource] - Defines the target resource this access is granted or
   * denied for. This is only optional if the resource is previously defined.
   * If not defined and omitted, this will throw.
   * @param [attributes] - Defines the resource attributes for which the access
   * is granted for. If access is denied previously by calling `.deny()` this
   * will default to an empty array (which means no attributes allowed).
   * Otherwise (if granted before via `.grant()`) this will default to `["*"]`
   * (which means all attributes allowed.)
   *
   * @throws {AccessControlError} - If the access instance to be committed has
   * any invalid data.
   *
   * @returns - Self instance of `Access` so that you can chain and define
   * another access instance to be committed.
   */
  createAny(resource?: string | string[], attributes?: string | string[]): Access {
    return this._prepareAndCommit(Action.CREATE, Possession.ANY, resource, attributes);
  }
  /**
   * Alias of `createAny`
   * @private
   */
  create(resource?: string | string[], attributes?: string | string[]): Access {
    return this.createAny(resource, attributes);
  }

  /**
   * Sets the action to `"read"` and possession to `"own"` and commits the
   * current access instance to the underlying grant model.
   *
   * @param [resource] - Defines the target resource this access is granted or
   * denied for. This is only optional if the resource is previously defined.
   * If not defined and omitted, this will throw.
   * @param [attributes] - Defines the resource attributes for which the access
   * is granted for. If access is denied previously by calling `.deny()` this
   * will default to an empty array (which means no attributes allowed).
   * Otherwise (if granted before via `.grant()`) this will default to `["*"]`
   * (which means all attributes allowed.)
   *
   * @throws {AccessControlError} - If the access instance to be committed has
   * any invalid data.
   *
   * @returns - Self instance of `Access` so that you can chain and define
   * another access instance to be committed.
   */
  readOwn(resource?: string | string[], attributes?: string | string[]): Access {
    return this._prepareAndCommit(Action.READ, Possession.OWN, resource, attributes);
  }

  /**
   * Sets the action to `"read"` and possession to `"any"` and commits the
   * current access instance to the underlying grant model.
   *
   * @param [resource] - Defines the target resource this access is granted or
   * denied for. This is only optional if the resource is previously defined.
   * If not defined and omitted, this will throw.
   * @param [attributes] - Defines the resource attributes for which the access
   * is granted for. If access is denied previously by calling `.deny()` this
   * will default to an empty array (which means no attributes allowed).
   * Otherwise (if granted before via `.grant()`) this will default to `["*"]`
   * (which means all attributes allowed.)
   *
   * @throws {AccessControlError} - If the access instance to be committed has
   * any invalid data.
   *
   * @returns - Self instance of `Access` so that you can chain and define
   * another access instance to be committed.
   */
  readAny(resource?: string | string[], attributes?: string | string[]): Access {
    return this._prepareAndCommit(Action.READ, Possession.ANY, resource, attributes);
  }
  /**
   * Alias of `readAny`
   * @private
   */
  read(resource?: string | string[], attributes?: string | string[]): Access {
    return this.readAny(resource, attributes);
  }

  /**
   * Sets the action to `"update"` and possession to `"own"` and commits the
   * current access instance to the underlying grant model.
   *
   * @param [resource] -  Defines the target resource this access is granted or
   * denied for. This is only optional if the resource is previously defined.
   * If not defined and omitted, this will throw.
   * @param [attributes] -  Defines the resource attributes for which the
   * access is granted for. If access is denied previously by calling `.deny()`
   * this will default to an empty array (which means no attributes allowed).
   * Otherwise (if granted before via `.grant()`) this will default to `["*"]`
   * (which means all attributes allowed.)
   *
   * @throws {AccessControlError} - If the access instance to be committed has
   * any invalid data.
   *
   * @returns - Self instance of `Access` so that you can chain and define
   * another access instance to be committed.
   */
  updateOwn(resource?: string | string[], attributes?: string | string[]): Access {
    return this._prepareAndCommit(Action.UPDATE, Possession.OWN, resource, attributes);
  }

  /**
   * Sets the action to `"update"` and possession to `"any"` and commits the
   * current access instance to the underlying grant model.
   *
   * @param [resource] -  Defines the target resource this access is granted or
   * denied for. This is only optional if the resource is previously defined.
   * If not defined and omitted, this will throw.
   * @param [attributes] -  Defines the resource attributes for which the
   * access is granted for. If access is denied previously by calling `.deny()`
   * this will default to an empty array (which means no attributes allowed).
   * Otherwise (if granted before via `.grant()`) this will default to `["*"]`
   * (which means all attributes allowed.)
   *
   * @throws {AccessControlError} - If the access instance to be committed has
   * any invalid data.
   *
   * @returns - Self instance of `Access` so that you can chain and define
   * another access instance to be committed.
   */
  updateAny(resource?: string | string[], attributes?: string | string[]): Access {
    return this._prepareAndCommit(Action.UPDATE, Possession.ANY, resource, attributes);
  }
  /**
   * Alias of `updateAny`
   * @private
   */
  update(resource?: string | string[], attributes?: string | string[]): Access {
    return this.updateAny(resource, attributes);
  }

  /**
   * Sets the action to `"delete"` and possession to `"own"` and commits the
   * current access instance to the underlying grant model.
   *
   * @param [resource] -  Defines the target resource this access is granted or
   * denied for. This is only optional if the resource is previously defined.
   * If not defined and omitted, this will throw.
   * @param [attributes] -  Defines the resource attributes for which the
   * access is granted for. If access is denied previously by calling `.deny()`
   * this will default to an empty array (which means no attributes allowed).
   * Otherwise (if granted before via `.grant()`) this will default to `["*"]`
   * (which means all attributes allowed.)
   *
   * @throws {AccessControlError} - If the access instance to be committed has
   * any invalid data.
   *
   * @returns - Self instance of `Access` so that you can chain and define
   * another access instance to be committed.
   */
  deleteOwn(resource?: string | string[], attributes?: string | string[]): Access {
    return this._prepareAndCommit(Action.DELETE, Possession.OWN, resource, attributes);
  }

  /**
   * Sets the action to `"delete"` and possession to `"any"` and commits the
   * current access instance to the underlying grant model.
   *
   * @param [resource] -  Defines the target resource this access is granted or
   * denied for. This is only optional if the resource is previously defined.
   * If not defined and omitted, this will throw.
   * @param [attributes] -  Defines the resource attributes for which the
   * access is granted for. If access is denied previously by calling `.deny()`
   * this will default to an empty array (which means no attributes allowed).
   * Otherwise (if granted before via `.grant()`) this will default to `["*"]`
   * (which means all attributes allowed.)
   *
   * @throws {AccessControlError} - If the access instance to be committed has
   * any invalid data.
   *
   * @returns - Self instance of `Access` so that you can chain and define
   * another access instance to be committed.
   */
  deleteAny(resource?: string | string[], attributes?: string | string[]): Access {
    return this._prepareAndCommit(Action.DELETE, Possession.ANY, resource, attributes);
  }
  /**
   * Alias of `deleteAny`
   * @private
   */
  delete(resource?: string | string[], attributes?: string | string[]): Access {
    return this.deleteAny(resource, attributes);
  }

  // -------------------------------
  //  PRIVATE METHODS
  // -------------------------------

  /**
   * @private
   * @param action
   * @param possession
   * @param resource
   * @param attributes
   * @returns - Self instance of `Access`.
   */
  private _prepareAndCommit(
    action: Action | string,
    possession: Possession,
    resource?: string | string[],
    attributes?: string | string[]
  ): Access {
    this._.action = action;
    this._.possession = possession;
    if (resource) this._.resource = resource;

    // omitted ⇒ all attributes. For a grant this allows all; for a deny this
    // denies all (deny-overrides). Explicit `[]` is preserved.
    this._.attributes = attributes ? toStringArray(attributes) : ['*'];

    // fold pending `.during()` schedules into the condition (AND semantics).
    if (this._during.length > 0) {
      const leaves = this._during.map(
        (expr) => [`${this._pathPrefix}.now`, 'during', expr] as ConditionLeaf
      );
      const parts = this._.condition === undefined ? leaves : [this._.condition, ...leaves];
      this._.condition = parts.length === 1 ? parts[0] : { and: parts };
    }

    commitToGrants(this._grants, this._, false, this._pathPrefix, this._nameOpts);

    // announce the policy edit (grant/deny) before resetting per-action state.
    (this._ac as any)._emitChange(this._.denied ? 'deny' : 'grant', {
      role: this._.role,
      resource: this._.resource,
      action: this._.action,
      possession: this._.possession,
      attributes: this._.attributes
    });

    // important: reset per-action state for chained methods (attributes and the
    // condition from `.where()`/`.during()` apply only to the action just committed)
    this._.attributes = undefined;
    this._.condition = undefined;
    this._during = [];

    return this;
  }
}
