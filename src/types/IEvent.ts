// own modules
import type { AccessControlError } from '../core/AccessControlError.js';
import type { UnknownObject } from './UnknownObject.js';

/** Event names (the {@link AccessControlEvent} enum values). */
export type AccessControlEventName = 'access' | 'change' | 'error';

/**
 * Why a check was denied — makes denials debuggable in the audit log.
 * `undefined` when granted.
 */
export type AccessReason =
  | 'no_grant'
  | 'condition_failed'
  | 'require_failed'
  | 'ownership_failed'
  | 'strict';

/** Discriminator for a {@link ChangeEvent} (what kind of mutation occurred). */
export type ChangeType =
  | 'grant'
  | 'deny'
  | 'extend'
  | 'remove'
  | 'set_grants'
  | 'reset'
  | 'setup'
  | 'require'
  | 'lock';

/** Fields shared by every emitted event. */
export interface BaseEvent {
  /** The event name (`access` | `change` | `error`). */
  name: AccessControlEventName;
  /** Epoch milliseconds when the event was emitted. */
  timestamp: number;
}

/**
 * Emitted for every resolved check — granted and denied. This **is** the access
 * audit record. ⚠️ `context` may contain PII; handle accordingly.
 */
export interface AccessEvent extends BaseEvent {
  name: 'access';
  roles: string[];
  resource: string;
  /** The resource's category, when it is a `category/resource`. */
  category?: string;
  action: string;
  possession?: 'own' | 'any';
  granted: boolean;
  attributes: string[];
  /** Why it was denied (omitted when granted). */
  reason?: AccessReason;
  /** The merged check context (may contain PII). */
  context?: UnknownObject;
}

/** Emitted when the grants model or vocabulary mutates (policy-edit audit). */
export interface ChangeEvent extends BaseEvent {
  name: 'change';
  type: ChangeType;
  /** Mutation-specific details (e.g. `{ roles, resource, action }`). */
  detail?: UnknownObject;
}

/** Emitted when a check or operation throws. */
export interface ErrorEvent extends BaseEvent {
  name: 'error';
  error: AccessControlError;
  /** The operation that threw (e.g. `'check'`, `'grant'`). */
  operation: string;
  roles?: string[];
  resource?: string;
  action?: string;
}

/** Any event emitted by `AccessControl`. */
export type AccessControlEventPayload = AccessEvent | ChangeEvent | ErrorEvent;

/** An event listener callback. */
export type EventListener = (event: AccessControlEventPayload) => void;
