/**
 *  Enumerates the possible actions of a role.
 *  An action defines the type of an operation that will be executed on a
 *  "resource" by a "role".
 *  This is known as CRUD (CREATE, READ, UPDATE, DELETE).
 *  @enum {String}
 *  @readonly
 *  @memberof! AccessControl
 */
declare const Action: {
    /**
     *  Specifies a CREATE action to be performed on a resource.
     *  For example, an HTTP POST request or an INSERT database operation.
     *  @type {String}
     */
    CREATE: string;
    /**
     *  Specifies a READ action to be performed on a resource.
     *  For example, an HTTP GET request or an database SELECT operation.
     *  @type {String}
     */
    READ: string;
    /**
     *  Specifies an UPDATE action to be performed on a resource.
     *  For example, an HTTP PUT or POST request or an database UPDATE operation.
     *  @type {String}
     */
    UPDATE: string;
    /**
     *  Specifies a DELETE action to be performed on a resource.
     *  For example, an HTTP DELETE request or a database DELETE operation.
     *  @type {String}
     */
    DELETE: string;
};
export { Action };
