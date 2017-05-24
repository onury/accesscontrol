/**
 *  An interface that defines an access information to be queried.
 *  When you start a method chain with `AccessControl#can` method, you're
 *  actually building this query object which will be used to check the access
 *  permissions.
 *  @interface
 */
interface IQueryInfo {
    /**
     *  Indicates a single or multiple roles to be queried.
     *  @type {String|Array<String>}
     */
    role?: string | string[];
    /**
     *  Indicates the resource to be queried.
     *  @type {String}
     */
    resource?: string;
    /**
     *  Defines the type of the operation that is (or not) to be performed on
     *  the resource by the defined role(s).
     *  See {@link ?api=ac#AccessControl.Action|`AccessControl.Action` enumeration}
     *  for possible values.
     *  @type {String}
     */
    action?: string;
    /**
     *  Defines the possession of the resource for the specified action.
     *  See {@link ?api=ac#AccessControl.Possession|`AccessControl.Possession` enumeration}
     *  for possible values.
     *  @type {String}
     */
    possession?: string;
}
export { IQueryInfo };
