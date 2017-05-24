/**
 *  Error class specific to `AccessControl`.
 *  @readonly
 *  @name AccessControl.Error
 *  @class
 *  @static
 */
declare class AccessControlError extends Error {
    message: string;
    name: string;
    constructor(message?: string);
}
export { AccessControlError };
