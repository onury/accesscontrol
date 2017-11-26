"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = Object.setPrototypeOf ||
        ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
        function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };
    return function (d, b) {
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
/**
 *  Error class specific to `AccessControl`.
 *  @readonly
 *  @name AccessControl.Error
 *  @class
 *  @static
 */
var AccessControlError = /** @class */ (function (_super) {
    __extends(AccessControlError, _super);
    function AccessControlError(message) {
        if (message === void 0) { message = ''; }
        var _this = _super.call(this, message) /* istanbul ignore next */ || this;
        _this.message = message;
        _this.name = 'AccessControlError';
        // https://github.com/gotwarlost/istanbul/issues/690
        // http://stackoverflow.com/a/41429145/112731
        Object.setPrototypeOf(_this, AccessControlError.prototype);
        return _this;
    }
    return AccessControlError;
}(Error));
exports.AccessControlError = AccessControlError;
