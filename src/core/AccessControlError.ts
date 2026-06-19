/**
 * Options for constructing an {@link AccessControlError}. Extends the standard
 * `ErrorOptions` (so a `cause` can be attached) with optional structured
 * context for programmatic handling.
 */
export interface IAccessControlErrorOptions extends ErrorOptions {
  /**
   * Stable, machine-readable code for programmatic handling. Branch on this
   * instead of parsing `message` (messages are redacted by default and may
   * change wording). See {@link ErrorCode}.
   */
  code?: string;
  /** The role(s) this error relates to, if any. */
  role?: string | string[];
  /** The resource this error relates to, if any. */
  resource?: string;
  /** The action this error relates to, if any. */
  action?: string;
  /**
   * Set when the fault is "this check needs the async path" — i.e. an applicable
   * rule/gate carries a custom/async `{ fn }` condition. The engine uses it to
   * defer such checks to `grantedAsync`/`checkAsync`.
   */
  asyncRequired?: boolean;
}

/**
 * Error class specific to `AccessControl`.
 *
 * Consumers can check `err instanceof AccessControlError` to handle access
 * faults. When the fault originates from a lower-level error, it is attached as
 * `error.cause`; related `role`/`resource`/`action` context (when known) is
 * available as structured fields.
 */
export class AccessControlError extends Error {
  override name = 'AccessControlError';

  /** Stable, machine-readable error code ({@link ErrorCode}). */
  readonly code?: string;

  /** The role(s) this error relates to, if available. */
  readonly role?: string | string[];

  /** The resource this error relates to, if available. */
  readonly resource?: string;

  /** The action this error relates to, if available. */
  readonly action?: string;

  /** Whether this fault requires the async check path (custom/async `{ fn }`). */
  readonly asyncRequired?: boolean;

  constructor(message = '', options?: IAccessControlErrorOptions) {
    super(message, options);
    this.code = options?.code;
    this.role = options?.role;
    this.resource = options?.resource;
    this.action = options?.action;
    this.asyncRequired = options?.asyncRequired;
  }
}
