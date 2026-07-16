// dep modules
import { type DTRExp, type DTRExpSyntaxError, parse as parseDTRExp } from 'dtrexp';
import { Notation } from 'notation';
// own modules
import { AccessControlError } from '../core/index.js';
import { ErrorCode } from '../enums/index.js';
import type {
  ConditionFunction,
  ConditionJSON,
  ConditionLeaf,
  UnknownObject
} from '../types/index.js';
import { ecode, type } from './generic.js';

/**
 * Re-stamps an error's `code` with the engine's `errorCodePrefix`. Used at the
 * evaluator entry points so codes thrown by the internal eval helpers carry the
 * configured prefix without threading it through every function. Idempotent and
 * a no-op when there is no prefix.
 */
function restampCode(err: unknown, prefix: string): unknown {
  if (!prefix) return err;
  /* istanbul ignore next -- defensive: evaluator throws are always coded AC errors */
  if (!(err instanceof AccessControlError) || !err.code) return err;
  return new AccessControlError(err.message, {
    code: prefix + err.code,
    role: err.role,
    resource: err.resource,
    action: err.action,
    asyncRequired: err.asyncRequired,
    cause: err.cause
  });
}

// ----------------------
// CONDITION COMPILER
// ----------------------
// Compiles the author-facing *string sugar* form into the canonical JSON form
// that is stored (JSONB-friendly) and consumed by the evaluator.
// An array `[lhs, op, rhs]` is a comparison leaf; an object `{ and|or|not }` is
// a combinator; `{ fn, args }` is a custom-fn reference (kept as-is here, run in
// a later async phase). Strings — at any nesting level — are compiled to leaves.

/** Comparison operators kept in symbol form in the compiled triple. */
const COMPARISON_OPS = ['==', '!=', '>=', '<=', '>', '<'];
/**
 * Author-facing operator aliases, normalized to the canonical form at compile
 * time. `==`/`!=` are already *strict* (`===`/`!==` semantics), so the JS-style
 * `===`/`!==` spellings are accepted as synonyms — never stored, so the canonical
 * (serialized) triple always uses `==`/`!=`.
 */
const OP_ALIASES: Record<string, string> = { '===': '==', '!==': '!=' };
/** Membership operators. `nin` is intentionally dropped — use `not … in`. */
const MEMBERSHIP_OPS = ['in', 'contains'];
/** String operators. */
const STRING_OPS = ['matches', 'startsWith', 'endsWith'];
/** Time operators. */
const TIME_OPS = ['before', 'after', 'between', 'during'];
/** Network operator — explicit single-range alias (the list case folds into `in`). */
const NETWORK_OPS = ['cidr'];

const ALL_OPS = [...COMPARISON_OPS, ...MEMBERSHIP_OPS, ...STRING_OPS, ...TIME_OPS, ...NETWORK_OPS];

/**
 * Maximum `and`/`or`/`not` nesting depth accepted by {@link compileCondition}.
 * Bounds the recursive compiler/evaluator so a pathologically deep condition
 * tree (e.g. loaded from an untrusted store) cannot exhaust the stack on the
 * authorization path. Legitimate conditions are nowhere near this deep.
 */
const MAX_CONDITION_DEPTH = 100;

/** Upper bound on a `matches` pattern's source length (a coarse DoS guard). */
const MAX_REGEX_LENGTH = 1000;

/**
 * Conservative ReDoS guard for the `matches` operator. Rejects the classic
 * catastrophic-backtracking shape — a group quantified by an unbounded
 * quantifier whose body *also* contains an unbounded quantifier (star height
 * ≥ 2, e.g. `(a+)+`, `(.*)*`, `(\d+)*`) — and absurdly long patterns.
 *
 * This is a heuristic, not a proof: it blocks every well-known gadget shape but
 * cannot guarantee linear-time matching for arbitrary patterns (only a RE2-style
 * engine can). `matches` is therefore also opt-in via `policy.allowRegex`.
 *
 * @throws {AccessControlError} - If the pattern looks unsafe.
 */
function assertSafeRegex(src: string): void {
  if (src.length > MAX_REGEX_LENGTH) {
    throw new AccessControlError(`Regular expression too long (> ${MAX_REGEX_LENGTH}).`, {
      code: ErrorCode.UNSAFE_REGEX
    });
  }
  const quantGroup = /\(([^()]*)\)\s*(?:[*+]|\{\d+,\d*\})/g;
  let m = quantGroup.exec(src);
  while (m !== null) {
    if (/[*+]|\{\d+,\d*\}/.test(m[1])) {
      throw new AccessControlError(
        'Potentially catastrophic regular expression rejected (nested quantifier).',
        { code: ErrorCode.UNSAFE_REGEX }
      );
    }
    m = quantGroup.exec(src);
  }
}

/** Upper bound on a `during` expression's source length (a coarse DoS guard). */
const MAX_DTREXP_LENGTH = 1000;

/**
 * Upper bound on the `during` parse cache. Expressions originate from grant
 * authors (a real policy holds a handful of distinct strings), but grants may
 * be deserialized from an untrusted store and {@link evaluateCondition} is an
 * exported utility — an unbounded string-keyed map would be a memory-growth
 * vector. A miss past the bound only costs one cheap re-parse.
 */
const MAX_DTREXP_CACHE = 500;

/** Module-level `during` parse cache: dtrexp source → immutable compiled instance. */
const dtrexpCache = new Map<string, DTRExp>();

/**
 * Parses a `during` dtrexp expression — or returns the cached instance.
 * `DTRExp` instances are immutable ("parse once, evaluate many"); the cache is
 * FIFO-bounded by {@link MAX_DTREXP_CACHE}. Exported only as an internal test
 * hook (not part of the public API surface).
 *
 * @throws {AccessControlError} - If the expression is too long or malformed
 * (carries dtrexp's message and character position; original error as `cause`).
 */
export function getDTRExp(expression: string, errorCodePrefix: string = ''): DTRExp {
  if (expression.length > MAX_DTREXP_LENGTH) {
    throw new AccessControlError(`"during" expression too long (> ${MAX_DTREXP_LENGTH}).`, {
      code: ecode(errorCodePrefix, ErrorCode.INVALID_DTREXP)
    });
  }
  const cached = dtrexpCache.get(expression);
  if (cached) return cached;
  let dtr: DTRExp;
  try {
    dtr = parseDTRExp(expression);
  } catch (err) {
    // per the dtrexp contract, parse() only throws DTRExpSyntaxError — wrap
    // unconditionally (the `matches` invalid-regex precedent).
    const { position, message } = err as DTRExpSyntaxError;
    throw new AccessControlError(
      `Invalid "during" expression at position ${position}: ${message}`,
      { code: ecode(errorCodePrefix, ErrorCode.INVALID_DTREXP), cause: err }
    );
  }
  if (dtrexpCache.size >= MAX_DTREXP_CACHE) {
    dtrexpCache.delete(dtrexpCache.keys().next().value as string);
  }
  dtrexpCache.set(expression, dtr);
  return dtr;
}

const NUMERIC_RE = /^-?\d+(\.\d+)?$/;
const TIME_RE = /^\d{1,2}:\d{2}$/; // HH:MM time-of-day (wrapping `between`)
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/; // YYYY-MM-DD (lexical order == chronological)
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const CIDR_RE = /^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/;

/**
 * Splits a single expression string into tokens, treating a quoted run
 * (`'…'`/`"…"`) and a bracketed list (`[…]`) each as one token, and otherwise
 * splitting on whitespace.
 * @throws {AccessControlError} - On an unterminated quote or bracket.
 */
function tokenize(s: string): string[] {
  const tokens: string[] = [];
  const n = s.length;
  let i = 0;
  while (i < n) {
    while (i < n && /\s/.test(s[i])) i++;
    if (i >= n) break;
    const ch = s[i];
    if (ch === '"' || ch === "'") {
      let j = i + 1;
      while (j < n && s[j] !== ch) j++;
      if (j >= n) throw new AccessControlError(`Unterminated quote in condition: "${s}".`);
      tokens.push(s.slice(i, j + 1));
      i = j + 1;
    } else if (ch === '[') {
      let depth = 0;
      let j = i;
      while (j < n) {
        if (s[j] === '[') depth++;
        else if (s[j] === ']') depth--;
        if (depth === 0) break;
        j++;
      }
      if (depth !== 0) throw new AccessControlError(`Unterminated "[" in condition: "${s}".`);
      tokens.push(s.slice(i, j + 1));
      i = j + 1;
    } else {
      let j = i;
      while (j < n && !/\s/.test(s[j])) j++;
      tokens.push(s.slice(i, j));
      i = j;
    }
  }
  return tokens;
}

/** Whether a token is a notation path (e.g. `$.order.value` for prefix `$`). */
function isPath(token: string, pathPrefix: string): boolean {
  return token === pathPrefix || token.startsWith(`${pathPrefix}.`);
}

/** Whether a token is a quoted string literal. */
function isQuoted(token: string): boolean {
  return (
    token.length >= 2 &&
    ((token[0] === '"' && token.at(-1) === '"') || (token[0] === "'" && token.at(-1) === "'"))
  );
}

/** Splits a bracketed list `[a, b, c]` into its trimmed, non-empty members. */
function splitList(token: string): string[] {
  const inner = token.slice(1, -1).trim();
  if (inner === '') return [];
  return inner.split(',').map((s) => s.trim());
}

/**
 * Parses a single operand token into its typed literal — or keeps it as a path
 * string. Quotes force the string type; the barewords `true`/`false`/`null`
 * become those literals; a bareword that looks numeric becomes a number; `[…]`
 * becomes an array of parsed members. Use quotes to force the string form
 * (`"true"`, `"100"`, `"null"`).
 */
function parseOperand(token: string, pathPrefix: string): unknown {
  if (token === '') throw new AccessControlError('Empty operand in condition.');
  if (isPath(token, pathPrefix)) return token;
  if (token[0] === '[') return splitList(token).map((t) => parseOperand(t, pathPrefix));
  if (isQuoted(token)) return token.slice(1, -1);
  if (token === 'true') return true;
  if (token === 'false') return false;
  if (token === 'null') return null;
  if (NUMERIC_RE.test(token)) return Number(token);
  return token;
}

/** Validates the `between` bounds: inclusive; static start>end is an error. */
function validateBetween(rhs: unknown): void {
  if (!Array.isArray(rhs) || rhs.length !== 2) {
    throw new AccessControlError('"between" expects a list of exactly two bounds.');
  }
  const [a, b] = rhs;
  // time-of-day (HH:MM) allows start>end (overnight wrapping window) — skip.
  const bothTime =
    typeof a === 'string' && TIME_RE.test(a) && typeof b === 'string' && TIME_RE.test(b);
  if (bothTime) return;
  if (typeof a === 'number' && typeof b === 'number' && a > b) {
    throw new AccessControlError(`Invalid "between" range: ${a} > ${b}.`);
  }
  const bothDate =
    typeof a === 'string' && DATE_RE.test(a) && typeof b === 'string' && DATE_RE.test(b);
  if (bothDate && a > b) {
    throw new AccessControlError(`Invalid "between" range: ${a} > ${b}.`);
  }
}

/**
 * Validates a `during` rhs: a static, parseable, satisfiable dtrexp expression
 * string. A context path is rejected — the expression must be known at author
 * time (grants are serialized JSON; scheduling data does not come from the
 * check-time context). A parseable expression that can never match (dtrexp's
 * unsatisfiability lint, e.g. `D30 M2`) is an authoring bug on a security
 * policy and is rejected outright — the `validateBetween` spirit.
 */
function validateDuring(rhs: unknown, pathPrefix: string, errorCodePrefix: string): void {
  if (typeof rhs !== 'string' || rhs.trim() === '') {
    throw new AccessControlError('"during" expects a static dtrexp expression string.', {
      code: ecode(errorCodePrefix, ErrorCode.INVALID_DTREXP)
    });
  }
  if (isPath(rhs, pathPrefix)) {
    throw new AccessControlError(
      '"during" expects a static dtrexp expression, not a context path.',
      { code: ecode(errorCodePrefix, ErrorCode.INVALID_DTREXP) }
    );
  }
  const dtr = getDTRExp(rhs, errorCodePrefix);
  if (dtr.warnings.length > 0) {
    throw new AccessControlError(`"during" expression never matches: ${dtr.warnings[0].message}`, {
      code: ecode(errorCodePrefix, ErrorCode.DTREXP_NEVER_MATCHES)
    });
  }
}

/** Whether a value is an IP- or CIDR-shaped string literal. */
function isIpLike(v: unknown): boolean {
  return typeof v === 'string' && (IPV4_RE.test(v) || CIDR_RE.test(v));
}

/** Validates IP/CIDR literals so a malformed range throws at author time. */
function validateIpMembers(members: unknown[]): void {
  members.forEach((m) => {
    if (typeof m !== 'string') return; // a path member is resolved at check time
    const slash = m.indexOf('/');
    if (slash >= 0) {
      if (!CIDR_RE.test(m)) throw new AccessControlError(`Malformed CIDR: "${m}".`);
      const bits = Number(m.slice(slash + 1));
      if (bits < 0 || bits > 32) throw new AccessControlError(`Invalid CIDR prefix: "${m}".`);
    }
    const ip = slash >= 0 ? m.slice(0, slash) : m;
    if (IPV4_RE.test(ip) && ip.split('.').some((o) => Number(o) > 255)) {
      throw new AccessControlError(`Invalid IPv4 octet: "${m}".`);
    }
  });
}

/** Compiles a single sugar expression string into a canonical leaf (or `{not}`). */
function compileExpression(
  expr: string,
  pathPrefix: string,
  errorCodePrefix: string
): ConditionJSON {
  const t = tokenize(expr);
  if (t.length < 3) {
    throw new AccessControlError(`Invalid condition expression: "${expr}".`);
  }
  const lhs = parseOperand(t[0], pathPrefix);
  // `not` modifier compiles to a `{ not: leaf }` wrapper. The symbolic
  // `!=` stays its own operator and is handled below, not via this modifier.
  const negated = t[1] === 'not';
  const opIdx = negated ? 2 : 1;
  const rawOp = t[opIdx];
  const op = OP_ALIASES[rawOp] ?? rawOp;
  if (!ALL_OPS.includes(op)) {
    throw new AccessControlError(`Unknown operator "${rawOp}" in condition: "${expr}".`);
  }
  const rhsTokens = t.slice(opIdx + 1);
  if (rhsTokens.length === 0) {
    throw new AccessControlError(`Missing right-hand operand in condition: "${expr}".`);
  }
  const rhs = parseOperand(rhsTokens.join(' '), pathPrefix);

  if (op === 'between') validateBetween(rhs);
  if (op === 'during') validateDuring(rhs, pathPrefix, errorCodePrefix);
  if (op === 'cidr' && typeof rhs === 'string') validateIpMembers([rhs]);
  if (op === 'in' && Array.isArray(rhs) && rhs.some(isIpLike)) validateIpMembers(rhs);

  const leaf: ConditionLeaf = [lhs, op, rhs];
  return negated ? { not: leaf } : leaf;
}

/** Validates/normalizes an already-array leaf and its (typed) operands. */
function normalizeLeaf(
  node: unknown[],
  pathPrefix: string,
  errorCodePrefix: string
): ConditionJSON {
  if (node.length !== 3) {
    throw new AccessControlError(
      `Invalid condition leaf (expected [lhs, op, rhs]): ${JSON.stringify(node)}.`
    );
  }
  const rawOp = node[1];
  const op = typeof rawOp === 'string' ? (OP_ALIASES[rawOp] ?? rawOp) : rawOp;
  if (typeof op !== 'string' || !ALL_OPS.includes(op)) {
    throw new AccessControlError(`Unknown operator "${String(rawOp)}" in condition leaf.`);
  }
  if (op === 'between') validateBetween(node[2]);
  if (op === 'during') validateDuring(node[2], pathPrefix, errorCodePrefix);
  if (op === 'cidr' && typeof node[2] === 'string') validateIpMembers([node[2]]);
  if (op === 'in' && Array.isArray(node[2]) && node[2].some(isIpLike)) validateIpMembers(node[2]);
  // normalize an aliased operator (===/!==) into the canonical triple
  return (op === rawOp ? node : [node[0], op, node[2]]) as ConditionLeaf;
}

/**
 * Compiles a condition (string sugar and/or partial JSON) into the canonical
 * JSON form. Idempotent: canonical input passes through validated. Custom-fn
 * references (`{ fn, args }`) are returned unchanged (evaluated in a later
 * async phase).
 *
 * @param input - The author-supplied condition.
 * @param pathPrefix - The notation path sentinel (default `'$'`).
 * @returns The canonical, validated condition.
 * @throws {AccessControlError} - On malformed syntax, unknown operators or
 * statically-invalid ranges.
 *
 * @example
 * compileCondition('$.order.value > 100000');
 * // → ['$.order.value', '>', 100000]
 *
 * @example
 * compileCondition({ and: ['$.a == 1', '$.b != 2'] });
 * // → { and: [['$.a', '==', 1], ['$.b', '!=', 2]] }
 */
export function compileCondition(
  input: ConditionJSON,
  pathPrefix: string = '$',
  errorCodePrefix: string = '',
  _depth: number = 0
): ConditionJSON {
  const ic = ecode(errorCodePrefix, ErrorCode.INVALID_CONDITION);
  if (_depth > MAX_CONDITION_DEPTH) {
    throw new AccessControlError(`Condition nesting too deep (> ${MAX_CONDITION_DEPTH}).`, {
      code: ic
    });
  }
  if (typeof input === 'string') return compileExpression(input, pathPrefix, errorCodePrefix);
  if (Array.isArray(input)) return normalizeLeaf(input, pathPrefix, errorCodePrefix);
  if (type(input) === 'object') {
    const node = input as Record<string, unknown>;
    if ('fn' in node) return node as ConditionJSON; // custom fn — passthrough
    if ('and' in node) {
      if (!Array.isArray(node.and))
        throw new AccessControlError('"and" expects an array.', { code: ic });
      return {
        and: node.and.map((c) =>
          compileCondition(c as ConditionJSON, pathPrefix, errorCodePrefix, _depth + 1)
        )
      };
    }
    if ('or' in node) {
      if (!Array.isArray(node.or))
        throw new AccessControlError('"or" expects an array.', { code: ic });
      return {
        or: node.or.map((c) =>
          compileCondition(c as ConditionJSON, pathPrefix, errorCodePrefix, _depth + 1)
        )
      };
    }
    /* istanbul ignore next -- `in` arm mapping is imprecise through the TS transpile */
    if ('not' in node) {
      return {
        not: compileCondition(node.not as ConditionJSON, pathPrefix, errorCodePrefix, _depth + 1)
      };
    }
  }
  throw new AccessControlError(`Invalid condition: ${JSON.stringify(input)}.`, { code: ic });
}

// ----------------------
// CONDITION EVALUATOR
// ----------------------
// Evaluates a *canonical* condition (the compiler's output) against the merged
// check-time context, returning a boolean. Synchronous only —
// custom-fn (`{ fn }`) conditions are deferred to the async phase (P8).

const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];

/**
 * Derives the `$.now.*` fields from a `Date`, computed in the given
 * timezone (via `Intl`, no extra dependency). Weekday/month are short, lowercase
 * names; numbers are numeric; `date`/`time` are zero-padded strings.
 */
function deriveNow(date: Date, tz?: string): UnknownObject {
  const parts: Record<string, string> = {};
  const dtf = new Intl.DateTimeFormat('en-US', {
    timeZone: tz,
    weekday: 'short',
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false
  });
  for (const p of dtf.formatToParts(date)) parts[p.type] = p.value;
  let hour = parts.hour;
  /* istanbul ignore next -- defensive: some engines render midnight as 24 */
  if (hour === '24') hour = '00';
  const monthName = parts.month.toLowerCase();
  const monthNum = MONTHS.indexOf(monthName) + 1;
  const year = Number(parts.year);
  return {
    weekday: parts.weekday.toLowerCase(),
    month: monthName,
    year,
    day: Number(parts.day),
    date: `${year}-${String(monthNum).padStart(2, '0')}-${parts.day}`,
    time: `${hour}:${parts.minute}`,
    hour: Number(hour),
    minute: Number(parts.minute),
    // the raw instant — makes `$.now` itself a valid dtrexp DateInput (the
    // `{ epochMilliseconds }` shape), so `$.now during "…"` needs no special-casing.
    epochMilliseconds: date.getTime()
  };
}

/**
 * Builds the runtime context: shallow-clones the supplied context and expands
 * the reserved `now` key into its derived `$.now.*` fields (auto-injected,
 * overridable per check for tests). `tz` (also reserved) selects the timezone.
 */
function prepareContext(context: UnknownObject): UnknownObject {
  const tz = typeof context.tz === 'string' ? context.tz : undefined;
  const src = context.now;
  const date = src instanceof Date ? src : typeof src === 'string' ? new Date(src) : new Date();
  return { ...context, now: deriveNow(date, tz) };
}

/** Resolves an operand: a `$.`-path is read from context; anything else is a literal. */
function resolveOperand(v: unknown, ctx: UnknownObject, pathPrefix: string): unknown {
  if (typeof v === 'string' && isPath(v, pathPrefix)) {
    if (v === pathPrefix) return ctx;
    return new Notation(ctx).get(v.slice(pathPrefix.length + 1));
  }
  return v;
}

/** Converts an `HH:MM` string to minutes-since-midnight (robust to 1-digit hours). */
function timeToMinutes(s: string): number {
  const [h, m] = s.split(':');
  return Number(h) * 60 + Number(m);
}

/** Maps a value to a comparable number for `before`/`after` (time → minutes, date → epoch). */
function toComparable(v: unknown): number | string {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') {
    if (TIME_RE.test(v)) return timeToMinutes(v);
    const t = Date.parse(v);
    if (!Number.isNaN(t)) return t;
  }
  return v as string;
}

/**
 * Coerces a resolved `during` lhs to a dtrexp `DateInput`; `undefined` means
 * not date-like — the leaf then evaluates `false` (fail-closed), never throws.
 */
function toDateInput(
  v: unknown
): Date | number | string | { epochMilliseconds: number } | undefined {
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? undefined : v;
  if (typeof v === 'number') return Number.isFinite(v) ? v : undefined;
  if (typeof v === 'string') return Number.isNaN(Date.parse(v)) ? undefined : v;
  if (type(v) === 'object') {
    const epoch = (v as { epochMilliseconds?: unknown }).epochMilliseconds;
    // Number.isFinite() implies typeof number — no coercion, unlike isFinite()
    if (Number.isFinite(epoch)) return v as { epochMilliseconds: number };
  }
  return undefined;
}

/**
 * The system IANA timezone. Used as the `during` default so it stays
 * consistent with `deriveNow`, which also falls back to the system zone when
 * `context.tz` is absent — one tz story across the condition system. Not
 * memoized: Node re-resolves the zone when `process.env.TZ` changes at
 * runtime, and a stale memo would silently diverge from `deriveNow`.
 */
function systemTz(): string {
  return new Intl.DateTimeFormat().resolvedOptions().timeZone;
}

/** Inclusive `between`: numbers/dates ordered; `HH:MM` supports overnight wrap. */
function evalBetween(x: unknown, bounds: unknown[]): boolean {
  const [a, b] = bounds;
  const bothTime =
    typeof a === 'string' && TIME_RE.test(a) && typeof b === 'string' && TIME_RE.test(b);
  if (bothTime && typeof x === 'string') {
    const X = timeToMinutes(x);
    const A = timeToMinutes(a);
    const B = timeToMinutes(b);
    return A <= B ? X >= A && X <= B : X >= A || X <= B; // wrap when A > B
  }
  return (x as number) >= (a as number) && (x as number) <= (b as number);
}

/** Parses an IPv4 dotted-quad to a 32-bit unsigned integer. */
function ipv4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, o) => acc * 256 + Number(o), 0) >>> 0;
}

/** Whether `ip` matches a single IP or CIDR range member. */
function ipMatches(ip: string, member: string): boolean {
  const slash = member.indexOf('/');
  if (slash < 0) return ip === member;
  const base = member.slice(0, slash);
  const bits = Number(member.slice(slash + 1));
  if (!IPV4_RE.test(ip) || !IPV4_RE.test(base)) return false;
  if (bits === 0) return true;
  const mask = bits === 32 ? 0xffffffff : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

/** `in` membership: IP-aware when any rhs member is IP/CIDR-shaped. */
function evalIn(lhs: unknown, rhs: unknown[]): boolean {
  if (rhs.some(isIpLike)) {
    return typeof lhs === 'string' && rhs.some((m) => ipMatches(lhs, String(m)));
  }
  return rhs.includes(lhs);
}

/** Applies a comparison operator to resolved operands. */
function applyOp(
  op: string,
  lhs: unknown,
  rhs: unknown,
  allowRegex: boolean,
  tz?: string
): boolean {
  switch (op) {
    case '==':
      return lhs === rhs;
    case '!=':
      return lhs !== rhs;
    case '>':
      return (lhs as number) > (rhs as number);
    case '>=':
      return (lhs as number) >= (rhs as number);
    case '<':
      return (lhs as number) < (rhs as number);
    case '<=':
      return (lhs as number) <= (rhs as number);
    case 'in':
      return Array.isArray(rhs) && evalIn(lhs, rhs);
    case 'contains':
      if (Array.isArray(lhs)) return lhs.includes(rhs);
      return typeof lhs === 'string' && lhs.includes(String(rhs));
    case 'matches': {
      // opt-in: regex matching is off unless the policy enables it (ReDoS surface)
      if (!allowRegex) {
        throw new AccessControlError(
          'The "matches" operator is disabled. Enable it via policy.allowRegex.',
          { code: ErrorCode.REGEX_DISABLED }
        );
      }
      const src = String(rhs);
      assertSafeRegex(src); // reject catastrophic patterns before compiling
      try {
        return new RegExp(src).test(String(lhs));
      } catch {
        throw new AccessControlError(`Invalid regular expression: "${src}".`, {
          code: ErrorCode.UNSAFE_REGEX
        });
      }
    }
    case 'startsWith':
      return String(lhs).startsWith(String(rhs));
    case 'endsWith':
      return String(lhs).endsWith(String(rhs));
    case 'before':
      return toComparable(lhs) < toComparable(rhs);
    case 'after':
      return toComparable(lhs) > toComparable(rhs);
    case 'between':
      return Array.isArray(rhs) && evalBetween(lhs, rhs);
    case 'during': {
      const instant = toDateInput(lhs);
      if (typeof rhs !== 'string' || instant === undefined) return false; // fail-closed
      return getDTRExp(rhs).covers(instant, { tz: tz ?? systemTz() });
    }
    case 'cidr':
      return typeof lhs === 'string' && ipMatches(lhs, String(rhs));
    /* istanbul ignore next */
    default:
      throw new AccessControlError(`Unknown operator "${op}".`);
  }
}

/** Evaluates a canonical leaf `[lhs, op, rhs]` against the context. */
function evalLeaf(
  leaf: ConditionLeaf,
  ctx: UnknownObject,
  pathPrefix: string,
  allowRegex: boolean
): boolean {
  const [lhs, op, rhs] = leaf;
  const L = resolveOperand(lhs, ctx, pathPrefix);
  const R = Array.isArray(rhs)
    ? rhs.map((r) => resolveOperand(r, ctx, pathPrefix))
    : resolveOperand(rhs, ctx, pathPrefix);
  // reserved `tz` survives prepareContext's spread — `during` evaluates in it.
  const tz = typeof ctx.tz === 'string' ? ctx.tz : undefined;
  return applyOp(op as string, L, R, allowRegex, tz);
}

/** Recursively evaluates a canonical condition node. */
function evalNode(
  node: ConditionJSON,
  ctx: UnknownObject,
  pathPrefix: string,
  allowRegex: boolean
): boolean {
  if (Array.isArray(node)) return evalLeaf(node as ConditionLeaf, ctx, pathPrefix, allowRegex);
  if (type(node) === 'object') {
    const o = node as Record<string, unknown>;
    if (Array.isArray(o.and)) {
      return (o.and as ConditionJSON[]).every((c) => evalNode(c, ctx, pathPrefix, allowRegex));
    }
    if (Array.isArray(o.or)) {
      return (o.or as ConditionJSON[]).some((c) => evalNode(c, ctx, pathPrefix, allowRegex));
    }
    if ('not' in o) return !evalNode(o.not as ConditionJSON, ctx, pathPrefix, allowRegex);
    if ('fn' in o) {
      throw new AccessControlError(
        `Custom-function condition "${String(o.fn)}" requires the async check — use grantedAsync()/checkAsync().`,
        { asyncRequired: true, code: ErrorCode.ASYNC_REQUIRED }
      );
    }
  }
  if (typeof node === 'string') {
    throw new AccessControlError('Condition must be compiled before evaluation.', {
      code: ErrorCode.INVALID_CONDITION
    });
  }
  throw new AccessControlError(`Invalid condition node: ${JSON.stringify(node)}.`, {
    code: ErrorCode.INVALID_CONDITION
  });
}

/**
 * Evaluates a **canonical** condition (the {@link compileCondition} output)
 * against the merged check-time context, returning whether it holds.
 * The reserved `now` key is auto-injected and expanded into `$.now.*` fields
 * (overridable via `context.now` for deterministic tests; timezone via
 * `context.tz`). Synchronous: `{ fn }` conditions throw (deferred to P8).
 *
 * @param condition - A canonical condition (compile string sugar first).
 * @param context - The merged data bag; `$.`-paths resolve against it.
 * @param pathPrefix - The notation path sentinel (default `'$'`).
 * @param allowRegex - Whether the `matches` operator is permitted (default
 * `true` for direct use; the engine passes `policy.allowRegex`, default `false`).
 * @returns `true` if the condition holds for the context.
 * @throws {AccessControlError} - On an uncompiled/invalid node or a custom fn.
 *
 * @example
 * evaluateCondition(['$.order.value', '>', 100], { order: { value: 150 } }); // true
 */
export function evaluateCondition(
  condition: ConditionJSON,
  context: UnknownObject = {},
  pathPrefix: string = '$',
  allowRegex: boolean = true,
  errorCodePrefix: string = ''
): boolean {
  try {
    return evalNode(condition, prepareContext(context), pathPrefix, allowRegex);
  } catch (err) {
    throw restampCode(err, errorCodePrefix);
  }
}

/** Recursively evaluates a canonical node, awaiting custom `{ fn }` references. */
async function evalNodeAsync(
  node: ConditionJSON,
  ctx: UnknownObject,
  pathPrefix: string,
  registry: Record<string, ConditionFunction>,
  allowRegex: boolean
): Promise<boolean> {
  if (Array.isArray(node)) return evalLeaf(node as ConditionLeaf, ctx, pathPrefix, allowRegex);
  if (type(node) === 'object') {
    const o = node as Record<string, unknown>;
    if (Array.isArray(o.and)) {
      for (const c of o.and as ConditionJSON[]) {
        if (!(await evalNodeAsync(c, ctx, pathPrefix, registry, allowRegex))) return false;
      }
      return true;
    }
    if (Array.isArray(o.or)) {
      for (const c of o.or as ConditionJSON[]) {
        if (await evalNodeAsync(c, ctx, pathPrefix, registry, allowRegex)) return true;
      }
      return false;
    }
    if ('not' in o)
      return !(await evalNodeAsync(o.not as ConditionJSON, ctx, pathPrefix, registry, allowRegex));
    /* istanbul ignore next -- `in` arm mapping is imprecise through the TS transpile */
    if ('fn' in o) {
      const name = String(o.fn);
      // prototype-safe: only an own registry entry counts (an inherited member
      // name like `toString` must read as unknown, not the builtin function).
      const f = Object.hasOwn(registry, name) ? registry[name] : undefined;
      if (typeof f !== 'function') {
        throw new AccessControlError(`Unknown condition function: "${name}".`, {
          code: ErrorCode.UNKNOWN_CONDITION_FN
        });
      }
      return (await f(ctx, (o as { args?: unknown }).args)) === true;
    }
  }
  if (typeof node === 'string') {
    throw new AccessControlError('Condition must be compiled before evaluation.', {
      code: ErrorCode.INVALID_CONDITION
    });
  }
  throw new AccessControlError(`Invalid condition node: ${JSON.stringify(node)}.`, {
    code: ErrorCode.INVALID_CONDITION
  });
}

/**
 * Async sibling of {@link evaluateCondition}. Evaluates a **canonical**
 * condition, awaiting any custom `{ fn, args }` references resolved against the
 * registry (`ac.defineCondition`). Declarative leaves/combinators behave exactly
 * as the sync path; `and`/`or` short-circuit.
 *
 * @param condition - A canonical condition (compile string sugar first).
 * @param context - The merged data bag; `$.`-paths resolve against it.
 * @param pathPrefix - The notation path sentinel (default `'$'`).
 * @param registry - Custom condition functions by name.
 * @param allowRegex - Whether the `matches` operator is permitted (default
 * `true` for direct use; the engine passes `policy.allowRegex`, default `false`).
 * @returns A promise of whether the condition holds.
 */
export async function evaluateConditionAsync(
  condition: ConditionJSON,
  context: UnknownObject = {},
  pathPrefix: string = '$',
  registry: Record<string, ConditionFunction> = {},
  allowRegex: boolean = true,
  errorCodePrefix: string = ''
): Promise<boolean> {
  try {
    return await evalNodeAsync(
      condition,
      prepareContext(context),
      pathPrefix,
      registry,
      allowRegex
    );
  } catch (err) {
    throw restampCode(err, errorCodePrefix);
  }
}
