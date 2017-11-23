import { AccessControl } from '../';
import { IAccessInfo } from '../core';
/**
 *  Represents the inner `Access` class that helps build an access information
 *  to be granted or denied; and finally commits it to the underlying grants
 *  model. You can get a first instance of this class by calling
 *  `AccessControl#grant()` or `AccessControl#deny()` methods.
 *  @class
 *  @inner
 *  @memberof AccessControl
 */
declare class Access {
    /**
     *  Inner `IAccessInfo` object.
     *  @protected
     *  @type {IAccessInfo}
     */
    protected _: IAccessInfo;
    /**
     *  Main grants object.
     *  @protected
     *  @type {AccessControl}
     */
    protected _ac: AccessControl;
    /**
     *  Main grants object.
     *  @protected
     *  @type {Any}
     */
    protected _grants: any;
    /**
     *  Initializes a new instance of `Access`.
     *  @private
     *
     *  @param {AccessControl} ac
     *         AccessControl instance.
     *  @param {String|Array<String>|IAccessInfo} [roleOrInfo]
     *         Either an `IAccessInfo` object, a single or an array of
     *         roles. If an object is passed, possession and attributes
     *         properties are optional. CAUTION: if attributes is omitted,
     *         and access is not denied, it will default to `["*"]` which means
     *         "all attributes allowed". If possession is omitted, it will
     *         default to `"any"`.
     *  @param {Boolean} denied
     *         Specifies whether this `Access` is denied.
     */
    constructor(ac: AccessControl, roleOrInfo?: string | string[] | IAccessInfo, denied?: boolean);
    /**
     *  Specifies whether this access is initally denied.
     *  @name AccessControl~Access#denied
     *  @type {Boolean}
     *  @readonly
     */
    readonly denied: boolean;
    /**
     *  A chainer method that sets the role(s) for this `Access` instance.
     *  @param {String|Array<String>} value
     *         A single or array of roles.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    role(value: string | string[]): Access;
    /**
     *  A chainer method that sets the resource for this `Access` instance.
     *  @param {String|Array<String>} value
     *         Target resource for this `Access` instance.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    resource(value: string | string[]): Access;
    /**
     *  Sets the array of allowed attributes for this `Access` instance.
     *  @param {String|Array<String>} value
     *         Attributes to be set.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    attributes(value: string | string[]): Access;
    /**
     *  Sets the roles to be extended for this `Access` instance.
     *  @alias Access#inherit
     *  @name AccessControl~Access#extend
     *  @function
     *
     *  @param {String|Array<String>} roles
     *         A single or array of roles.
     *  @returns {Access}
     *           Self instance of `Access`.
     *
     *  @example
     *  ac.grant('user').createAny('video')
     *    .grant('admin').extend('user');
     *  const permission = ac.can('admin').createAny('video');
     *  console.log(permission.granted); // true
     */
    extend(roles: string | string[]): Access;
    /**
     *  Alias of `extend`.
     *  @private
     */
    inherit(roles: string | string[]): Access;
    /**
     *  Shorthand to switch to a new `Access` instance with a different role
     *  within the method chain.
     *
     *  @param {String|Array<String>|IAccessInfo} [roleOrInfo]
     *         Either a single or an array of roles or an
     *         {@link ?api=ac#AccessControl~IAccessInfo|`IAccessInfo` object}.
     *
     *  @returns {Access}
     *           A new `Access` instance.
     *
     *  @example
     *  ac.grant('user').createOwn('video')
     *    .grant('admin').updateAny('video');
     */
    grant(roleOrInfo?: string | string[] | IAccessInfo): Access;
    /**
     *  Shorthand to switch to a new `Access` instance with a different
     *  (or same) role within the method chain.
     *
     *  @param {String|Array<String>|IAccessInfo} [roleOrInfo]
     *         Either a single or an array of roles or an
     *         {@link ?api=ac#AccessControl~IAccessInfo|`IAccessInfo` object}.
     *
     *  @returns {Access}
     *           A new `Access` instance.
     *
     *  @example
     *  ac.grant('admin').createAny('video')
     *    .deny('user').deleteAny('video');
     */
    deny(roleOrInfo?: string | string[] | IAccessInfo): Access;
    /**
     *  Chainable, convenience shortcut for {@link ?api=ac#AccessControl#lock|`AccessControl#lock()`}.
     *  @returns {Access}
     */
    lock(): Access;
    /**
     *  Sets the action to `"create"` and possession to `"own"` and commits the
     *  current access instance to the underlying grant model.
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid
     *  data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    createOwn(resource?: string | string[], attributes?: string | string[]): Access;
    /**
     *  Sets the action to `"create"` and possession to `"any"` and commits the
     *  current access instance to the underlying grant model.
     *  @alias Access#create
     *  @name AccessControl~Access#createAny
     *  @function
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    createAny(resource?: string | string[], attributes?: string | string[]): Access;
    /**
     *  Alias of `createAny`
     *  @private
     */
    create(resource?: string | string[], attributes?: string | string[]): Access;
    /**
     *  Sets the action to `"read"` and possession to `"own"` and commits the
     *  current access instance to the underlying grant model.
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    readOwn(resource?: string | string[], attributes?: string | string[]): Access;
    /**
     *  Sets the action to `"read"` and possession to `"any"` and commits the
     *  current access instance to the underlying grant model.
     *  @alias Access#read
     *  @name AccessControl~Access#readAny
     *  @function
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    readAny(resource?: string | string[], attributes?: string | string[]): Access;
    /**
     *  Alias of `readAny`
     *  @private
     */
    read(resource?: string | string[], attributes?: string | string[]): Access;
    /**
     *  Sets the action to `"update"` and possession to `"own"` and commits the
     *  current access instance to the underlying grant model.
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    updateOwn(resource?: string | string[], attributes?: string | string[]): Access;
    /**
     *  Sets the action to `"update"` and possession to `"any"` and commits the
     *  current access instance to the underlying grant model.
     *  @alias Access#update
     *  @name AccessControl~Access#updateAny
     *  @function
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    updateAny(resource?: string | string[], attributes?: string | string[]): Access;
    /**
     *  Alias of `updateAny`
     *  @private
     */
    update(resource?: string | string[], attributes?: string | string[]): Access;
    /**
     *  Sets the action to `"delete"` and possession to `"own"` and commits the
     *  current access instance to the underlying grant model.
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    deleteOwn(resource?: string | string[], attributes?: string | string[]): Access;
    /**
     *  Sets the action to `"delete"` and possession to `"any"` and commits the
     *  current access instance to the underlying grant model.
     *  @alias Access#delete
     *  @name AccessControl~Access#deleteAny
     *  @function
     *
     *  @param {String|Array<String>} [resource]
     *         Defines the target resource this access is granted or denied for.
     *         This is only optional if the resource is previously defined.
     *         If not defined and omitted, this will throw.
     *  @param {String|Array<String>} [attributes]
     *         Defines the resource attributes for which the access is granted
     *         for. If access is denied previously by calling `.deny()` this
     *         will default to an empty array (which means no attributes allowed).
     *         Otherwise (if granted before via `.grant()`) this will default
     *         to `["*"]` (which means all attributes allowed.)
     *
     *  @throws {AccessControlError}
     *          If the access instance to be committed has any invalid data.
     *
     *  @returns {Access}
     *           Self instance of `Access` so that you can chain and define
     *           another access instance to be committed.
     */
    deleteAny(resource?: string | string[], attributes?: string | string[]): Access;
    /**
     *  Alias of `deleteAny`
     *  @private
     */
    delete(resource?: string | string[], attributes?: string | string[]): Access;
    /**
     *  @private
     *  @param {String} action     [description]
     *  @param {String} possession [description]
     *  @param {String|Array<String>} resource   [description]
     *  @param {String|Array<String>} attributes [description]
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    private _prepareAndCommit(action, possession, resource?, attributes?);
}
export { Access };
