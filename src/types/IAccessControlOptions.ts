// own modules
import type { Emitter } from '../core/Emitter.js';
import type { Charset } from '../enums/Charset.js';
import type { ConditionFunction, ConditionJSON } from './ICondition.js';
import type { UnknownObject } from './UnknownObject.js';

/**
 * Ownership resolver function. Receives the merged check context and
 * returns whether the requester owns the resource record under check. Takes
 * precedence over {@link IPolicy.ownerField}.
 */
export type OwnerResolver = (context: UnknownObject) => boolean;

/**
 * Strict-mode switches. `policy.strict` may also be a boolean: `true` =
 * all on, `false` = all lenient.
 */
export interface IStrictOptions {
  /**
   * Governs `own` checks when a resolver IS configured but ownership can't be
   * verified — record/owner missing. `true` (**default**): deny (secure).
   * `false`: v2 behavior — resolve the `own` attribute set, ownership left to
   * the consumer. (With no resolver configured, `own` is never gated.)
   */
  checks?: boolean;
  /**
   * Throw on an unknown role at check time. `true` (**default**) matches
   * the existing throw-on-unknown-role behavior; `false` ⇒ unknown role
   * contributes nothing (no throw).
   */
  roles?: boolean;
  /**
   * Throw on an unknown action at check time instead of silently returning
   * `granted:false`. **Default `false`** (an ungranted action denies, it doesn't
   * throw). Enable to catch typos — best paired with `setup({ actions })`
   * declaring your full vocabulary, so only true typos throw (a declared-but-
   * ungranted action still returns `granted:false`). The known set = CRUD ∪
   * actions present in the grants ∪ declared `setup({ actions })` ∪
   * {@link IPolicy.actions}; CRUD verbs are always known.
   */
  actions?: boolean;
  /**
   * Throw on an unknown resource at check time instead of silently returning
   * `granted:false`. **Default `false`** (an ungranted resource denies, it
   * doesn't throw). Enable to catch typos — best paired with `setup({ resources })`
   * declaring your vocabulary. Known set = resources present in the grants ∪
   * declared vocabulary ∪ {@link IPolicy.resources}.
   */
  resources?: boolean;
}

/**
 * Engine **mechanics & security** — how the library parses, validates and
 * reports, independent of *your* authorization model. Constructor-only.
 *
 * Compare with {@link IPolicy} (your domain's authorization model) and
 * `context` (the data conditions read). Rule of thumb: *if it's about the
 * library's behavior, it's `engine`; if it's about your domain, it's `policy`;
 * if a condition reads it with `$.`, it's `context`.*
 */
export interface IEngine {
  /**
   * The notation path sentinel used in conditions. With the default
   * `'$'`, `$.order.value` is a path and `foo` is a literal. Set a different
   * prefix (e.g. `'@'`) when your data contains `$.`-leading literal strings.
   */
  pathPrefix?: string;
  /**
   * Whether the `matches` (regular-expression) condition operator is permitted.
   * **Default `false`** — opt-in, because a regular expression from a grant
   * store is a ReDoS (catastrophic-backtracking) surface. When enabled, patterns
   * are still screened for the well-known catastrophic shapes, but that screen is
   * a heuristic, not a linear-time guarantee — only enable it for trusted grant
   * sources.
   */
  allowRegex?: boolean;
  /**
   * Allowed character set for consumer-supplied names (roles, resources,
   * actions, groups, categories). **Default {@link Charset.ASCII}.** Use
   * {@link Charset.UNICODE} for internationalized names — but note the homograph
   * risk documented on that enum. Structural characters (`/ : $ * !`) and the
   * reserved prototype keywords are always rejected regardless.
   */
  charset?: Charset;
  /**
   * When `true` (**default**), error **messages** omit caller-supplied values
   * (names, the raw query/grant object) to avoid leaking request data into logs.
   * The values remain available on the error's structured fields
   * (`err.role`/`err.action`/`err.resource`) and `err.code`. Set `false` to get
   * verbose messages (`… Got: "…".`) during development.
   */
  safeErrors?: boolean;
  /**
   * Optional string prepended to every {@link AccessControlError} `code`
   * (default `''`). Use it to namespace AC codes against your own — e.g.
   * `'AC_'` makes `err.code === 'AC_ROLE_NOT_FOUND'`. **Note:** with a prefix
   * set, compare against the prefixed value (`err.code === 'AC_' +
   * ErrorCode.ROLE_NOT_FOUND`), since the bare-enum comparison no longer matches.
   */
  errorCodePrefix?: string;
}

/**
 * Authorization **model** — how the engine should interpret your grants for
 * *your* domain: how ownership is determined, and how strict the vocabulary is.
 * Constructor-only. Compare with {@link IEngine} (library mechanics) and
 * `context` (condition data).
 */
export interface IPolicy {
  /**
   * Field on the resource record that holds the owner id. Ownership is
   * `context.user.id === context.<resource>[ownerField]`. Ignored if
   * {@link IPolicy.owner} is set.
   */
  ownerField?: string;
  /**
   * Custom ownership resolver. Wins over {@link IPolicy.ownerField}.
   */
  owner?: OwnerResolver;
  /**
   * Strict-mode switches. `true` = all on, `false` = all lenient, or an
   * object for per-key control. Defaults: `checks` and `roles` **on** (secure),
   * `actions` and `resources` **off** (an ungranted action/resource denies, it
   * doesn't throw). Enable `actions`/`resources` for loud typo-protection —
   * ideally with `setup()` declaring your vocabulary — and pair with
   * {@link AccessControl#tryCan} on the request path.
   */
  strict?: boolean | IStrictOptions;
  /**
   * Optional explicit allow-list of **custom** action names, added to the
   * strict-mode known set (CRUD is always known). Equivalent to declaring them
   * with `setup({ actions })`.
   */
  actions?: string[];
  /** Optional explicit allow-list of resource names for strict mode. */
  resources?: string[];
}

/**
 * Options bag for the `AccessControl` constructor:
 * `new AccessControl(grants, { engine, policy, context })`.
 *
 * - **`engine`** — library mechanics & security (parsing, charset, error output).
 * - **`policy`** — your domain's authorization model (ownership, strict vocab).
 * - **`context`** — ambient data your conditions read via `$.`.
 */
export interface IAccessControlOptions {
  /** Engine mechanics & security (constructor-only). See {@link IEngine}. */
  engine?: IEngine;
  /** Authorization model for your domain (constructor-only). See {@link IPolicy}. */
  policy?: IPolicy;
  /**
   * Ambient **context** defaults, readable from conditions via `$.`. Merged with
   * — and overridden by — per-check context (`can(role, context)` / `.with()`).
   */
  context?: UnknownObject;
}

/**
 * Internal, fully-resolved options threaded into a permission check (engine
 * policy + the merged context). Not part of the public authoring surface.
 */
export interface IResolveOptions {
  /** Notation path sentinel (default `'$'`). */
  pathPrefix?: string;
  /** Merged check context (ambient + per-check). */
  context?: UnknownObject;
  /** Resource owner field. */
  ownerField?: string;
  /** Custom ownership resolver. */
  owner?: OwnerResolver;
  /** `strict.checks` resolved value (default `true`). */
  strictChecks?: boolean;
  /** `strict.roles` resolved value (default `true`). */
  strictRoles?: boolean;
  /** `strict.actions` resolved value (default `false`). */
  strictActions?: boolean;
  /** `strict.resources` resolved value (default `false`). */
  strictResources?: boolean;
  /** Whether the `matches` regex operator is permitted (default `false`). */
  allowRegex?: boolean;
  /** Resolved allowed-name pattern (`engine.charset`), default ASCII. */
  charset?: RegExp;
  /** `engine.safeErrors` resolved value (default `true`). */
  safeErrors?: boolean;
  /** `engine.errorCodePrefix` resolved value (default `''`). */
  errorCodePrefix?: string;
  /** Explicit action allow-list, merged into the strict known-actions set. */
  policyActions?: string[];
  /** Explicit resource allow-list, merged into the strict known-resources set. */
  policyResources?: string[];
  /**
   * Declared role vocabulary — qualified members + group names. Used to
   * resolve dynamic group inheritance and as the strict known-roles set.
   */
  vocabRoles?: string[];
  /** Declared resource vocabulary — qualified members + category names. */
  vocabResources?: string[];
  /** Declared action vocabulary, feeds the strict known-actions set. */
  vocabActions?: string[];
  /**
   * Mandatory restriction gates, keyed by scope. Every applicable gate
   * (global + the resource's category + the resource itself) must pass or the
   * check is denied — `require()` can only restrict, never grant.
   */
  requirements?: IRequirements;
  /**
   * Registered custom condition functions by name, used by the async
   * resolver to evaluate `{ fn, args }` conditions.
   */
  conditions?: Record<string, ConditionFunction>;
  /** The instance event emitter; used to emit `access`/`error` on a check. */
  emitter?: Emitter;
  /**
   * Fail-closed mode (set by `AccessControl#tryCan`). When `true`, any error
   * during a check — invalid query, strict violation, async-required on the sync
   * path — resolves to a denial (`granted:false`, `attributes:[]`) instead of
   * throwing. The `error` event still fires for observability.
   */
  safe?: boolean;
}

/**
 * Compiled `require()` gates by scope. Conditions use the same engine as
 * `.where()`.
 */
export interface IRequirements {
  /** Gates applied to every check. */
  global: ConditionJSON[];
  /** Gates applied to checks whose resource belongs to the keyed category. */
  categories: Record<string, ConditionJSON[]>;
  /** Gates applied to checks on the keyed resource. */
  resources: Record<string, ConditionJSON[]>;
}
