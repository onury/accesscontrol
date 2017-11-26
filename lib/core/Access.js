"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var core_1 = require("../core");
var enums_1 = require("../enums");
var utils_1 = require("../utils");
/**
 *  Represents the inner `Access` class that helps build an access information
 *  to be granted or denied; and finally commits it to the underlying grants
 *  model. You can get a first instance of this class by calling
 *  `AccessControl#grant()` or `AccessControl#deny()` methods.
 *  @class
 *  @inner
 *  @memberof AccessControl
 */
var Access = /** @class */ (function () {
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
    function Access(ac, roleOrInfo, denied) {
        if (denied === void 0) { denied = false; }
        /**
         *  Inner `IAccessInfo` object.
         *  @protected
         *  @type {IAccessInfo}
         */
        this._ = {};
        this._ac = ac;
        this._grants = ac._grants;
        this._.denied = denied;
        if (typeof roleOrInfo === 'string' || Array.isArray(roleOrInfo)) {
            this.role(roleOrInfo);
        }
        else if (utils_1.utils.type(roleOrInfo) === 'object') {
            if (Object.keys(roleOrInfo).length === 0) {
                throw new core_1.AccessControlError('Invalid IAccessInfo: {}');
            }
            // if an IAccessInfo instance is passed and it has 'action' defined, we
            // should directly commit it to grants.
            roleOrInfo.denied = denied;
            this._ = utils_1.utils.resetAttributes(roleOrInfo);
            if (utils_1.utils.isInfoFulfilled(this._))
                utils_1.utils.commitToGrants(this._grants, this._, true);
        }
        else if (roleOrInfo !== undefined) {
            // undefined is allowed (`roleOrInfo` can be omitted) but throw if
            // some other type is passed.
            throw new core_1.AccessControlError('Invalid role(s), expected a valid string, string[] or IAccessInfo.');
        }
    }
    Object.defineProperty(Access.prototype, "denied", {
        // -------------------------------
        //  PUBLIC PROPERTIES
        // -------------------------------
        /**
         *  Specifies whether this access is initally denied.
         *  @name AccessControl~Access#denied
         *  @type {Boolean}
         *  @readonly
         */
        get: function () {
            return this._.denied;
        },
        enumerable: true,
        configurable: true
    });
    // -------------------------------
    //  PUBLIC METHODS
    // -------------------------------
    /**
     *  A chainer method that sets the role(s) for this `Access` instance.
     *  @param {String|Array<String>} value
     *         A single or array of roles.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    Access.prototype.role = function (value) {
        // in case chain is not terminated (e.g. `ac.grant('user')`) we'll
        // create/commit the roles to grants with an empty object.
        utils_1.utils.preCreateRoles(this._grants, value);
        this._.role = value;
        return this;
    };
    /**
     *  A chainer method that sets the resource for this `Access` instance.
     *  @param {String|Array<String>} value
     *         Target resource for this `Access` instance.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    Access.prototype.resource = function (value) {
        // this will throw if any item fails
        utils_1.utils.hasValidNames(value, true);
        this._.resource = value;
        return this;
    };
    /**
     *  Sets the array of allowed attributes for this `Access` instance.
     *  @param {String|Array<String>} value
     *         Attributes to be set.
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    Access.prototype.attributes = function (value) {
        this._.attributes = value;
        return this;
    };
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
    Access.prototype.extend = function (roles) {
        utils_1.utils.extendRole(this._grants, this._.role, roles);
        return this;
    };
    /**
     *  Alias of `extend`.
     *  @private
     */
    Access.prototype.inherit = function (roles) {
        this.extend(roles);
        return this;
    };
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
    Access.prototype.grant = function (roleOrInfo) {
        return (new Access(this._ac, roleOrInfo, false)).attributes(['*']);
    };
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
    Access.prototype.deny = function (roleOrInfo) {
        return (new Access(this._ac, roleOrInfo, true)).attributes([]);
    };
    /**
     *  Chainable, convenience shortcut for {@link ?api=ac#AccessControl#lock|`AccessControl#lock()`}.
     *  @returns {Access}
     */
    Access.prototype.lock = function () {
        utils_1.utils.lockAC(this._ac);
        return this;
    };
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
    Access.prototype.createOwn = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.CREATE, enums_1.Possession.OWN, resource, attributes);
    };
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
    Access.prototype.createAny = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.CREATE, enums_1.Possession.ANY, resource, attributes);
    };
    /**
     *  Alias of `createAny`
     *  @private
     */
    Access.prototype.create = function (resource, attributes) {
        return this.createAny(resource, attributes);
    };
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
    Access.prototype.readOwn = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.READ, enums_1.Possession.OWN, resource, attributes);
    };
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
    Access.prototype.readAny = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.READ, enums_1.Possession.ANY, resource, attributes);
    };
    /**
     *  Alias of `readAny`
     *  @private
     */
    Access.prototype.read = function (resource, attributes) {
        return this.readAny(resource, attributes);
    };
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
    Access.prototype.updateOwn = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.UPDATE, enums_1.Possession.OWN, resource, attributes);
    };
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
    Access.prototype.updateAny = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.UPDATE, enums_1.Possession.ANY, resource, attributes);
    };
    /**
     *  Alias of `updateAny`
     *  @private
     */
    Access.prototype.update = function (resource, attributes) {
        return this.updateAny(resource, attributes);
    };
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
    Access.prototype.deleteOwn = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.DELETE, enums_1.Possession.OWN, resource, attributes);
    };
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
    Access.prototype.deleteAny = function (resource, attributes) {
        return this._prepareAndCommit(enums_1.Action.DELETE, enums_1.Possession.ANY, resource, attributes);
    };
    /**
     *  Alias of `deleteAny`
     *  @private
     */
    Access.prototype.delete = function (resource, attributes) {
        return this.deleteAny(resource, attributes);
    };
    // -------------------------------
    //  PRIVATE METHODS
    // -------------------------------
    /**
     *  @private
     *  @param {String} action     [description]
     *  @param {String} possession [description]
     *  @param {String|Array<String>} resource   [description]
     *  @param {String|Array<String>} attributes [description]
     *  @returns {Access}
     *           Self instance of `Access`.
     */
    Access.prototype._prepareAndCommit = function (action, possession, resource, attributes) {
        this._.action = action;
        this._.possession = possession;
        if (resource)
            this._.resource = resource;
        if (this._.denied) {
            this._.attributes = [];
        }
        else {
            // if omitted and not denied, all attributes are allowed
            this._.attributes = attributes ? utils_1.utils.toStringArray(attributes) : ['*'];
        }
        utils_1.utils.commitToGrants(this._grants, this._, false);
        // important: reset attributes for chained methods
        this._.attributes = undefined;
        return this;
    };
    return Access;
}());
exports.Access = Access;
