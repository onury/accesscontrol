// own modules
import type { UnknownObject } from '../types/index.js';

// ----------------------
// GENERIC UTILS
// ----------------------

/**
 * Gets the type of the given object.
 * @param o
 */
export function type(o: unknown): string {
  return Object.prototype.toString
    .call(o)
    .match(/\s(\w+)/i)[1]
    .toLowerCase();
}

/**
 * Specifies whether the property/key is defined on the given object.
 * @param o
 * @param propName
 */
export function hasDefined(o: UnknownObject, propName: string): boolean {
  return Object.hasOwn(o, propName) && o[propName] !== undefined;
}

/**
 * Builds the dynamic-detail suffix for an error message, honoring `safeErrors`.
 * When `safe` (the default), returns `''` so no caller-supplied value is echoed
 * into the message (the value still travels in the error's structured fields).
 * When not safe (`policy.safeErrors:false`), returns a `Got: …` suffix for
 * developer ergonomics.
 * @param safe - The resolved `safeErrors` flag.
 * @param value - The dynamic value to (conditionally) include.
 */
export function detail(safe: boolean, value: unknown): string {
  if (safe) return '';
  const v = typeof value === 'string' ? `"${value}"` : JSON.stringify(value);
  return ` Got: ${v}.`;
}

/**
 * Applies the configured `engine.errorCodePrefix` to an {@link ErrorCode}.
 * With the default empty prefix the code is returned unchanged; with a prefix
 * (e.g. `"AC_"`) it becomes `"AC_ROLE_NOT_FOUND"` so codes can't collide with a
 * consumer's own error codes.
 * @param prefix - The resolved code prefix (may be `undefined`/empty).
 * @param code - The bare {@link ErrorCode} value.
 */
export function ecode(prefix: string | undefined, code: string): string {
  return prefix ? prefix + code : code;
}

/**
 * Converts the given (string) value into an array of string. Note that
 * this does not throw if the value is not a string or array. It will
 * silently return `[]` (empty array). So where ever it's used, the host
 * function should consider throwing.
 * @param value
 */
export function toStringArray(value: unknown): string[] {
  if (Array.isArray(value)) return value;
  if (typeof value === 'string') return value.trim().split(/\s*[;,]\s*/);
  return [];
}

/**
 * Checks whether the given array consists of non-empty string items.
 * (Array can be empty but no item should be an empty string.)
 * @param arr - Array to be checked.
 */
export function isFilledStringArray(arr: unknown[]): boolean {
  if (!arr || !Array.isArray(arr)) return false;
  for (const s of arr) {
    if (typeof s !== 'string' || s.trim() === '') return false;
  }
  return true;
}

/**
 * Checks whether the given value is an empty array.
 * @param value - Value to be checked.
 */
export function isEmptyArray(value: unknown): boolean {
  return Array.isArray(value) && value.length === 0;
}

/**
 * If an attribute list contains **only** negations (e.g. `['!password']`),
 * implies a leading `'*'` so it means "all attributes except...". A list
 * with at least one positive glob, or an empty list, is returned unchanged.
 * @param attributes
 */
export function impliedStar(attributes: string[]): string[] {
  if (attributes.length === 0) return attributes;
  const allNegated = attributes.every((a: string) => a.trim().startsWith('!'));
  return allNegated ? ['*', ...attributes] : attributes;
}

/**
 * Ensures that the pushed item is unique in the target array.
 * @param arr - Target array.
 * @param item - Item to be pushed to array.
 */
export function pushUniq(arr: string[], item: string): string[] {
  if (arr.indexOf(item) < 0) arr.push(item);
  return arr;
}

/**
 * Concats the given two arrays and ensures all items are unique.
 * @param arrA
 * @param arrB
 */
export function uniqConcat(arrA: string[], arrB: string[]): string[] {
  const arr: string[] = arrA.concat();
  arrB.forEach((b: string) => {
    pushUniq(arr, b);
  });
  return arr;
}

/**
 * Subtracts the second array from the first.
 * @param arrA
 * @param arrB
 */
export function subtractArray(arrA: string[], arrB: string[]): string[] {
  return arrA.concat().filter((a) => arrB.indexOf(a) === -1);
}

/**
 * Recursively freezes the given value, making it (and every nested object and
 * array it contains) immutable. Primitives, `null` and functions pass through
 * unchanged.
 *
 * The v3 grants model nests grant rules inside arrays
 * (`resource.action -> IGrant[]`), so a shallow freeze would freeze the array
 * but leave each rule object mutable — a lock-bypass. This recurses into array
 * elements (an array's own property names include its indices) and object
 * values alike, freezing children before the container.
 *
 * @param o - Value to deep-freeze.
 * @returns The same value, now deeply frozen.
 */
export function deepFreeze<T>(o: T): T {
  if (o === null || typeof o !== 'object') return o;
  for (const key of Object.getOwnPropertyNames(o)) {
    deepFreeze((o as Record<string, unknown>)[key]);
  }
  return Object.freeze(o);
}

/**
 * Similar to JS .forEach, except this allows for breaking out early,
 * (before all iterations are executed) by returning `false`.
 * @param array
 * @param callback
 * @param thisArg
 */
export function each(array: unknown[], callback: any, thisArg: unknown | null = null) {
  const length = array.length;
  let index = -1;
  while (++index < length) {
    if (callback.call(thisArg, array[index], index, array) === false) break;
  }
}

/**
 * Iterates through the keys of the given object. Breaking out early is
 * possible by returning `false`.
 * @param object
 * @param callback
 * @param thisArg
 */
export function eachKey(object: UnknownObject, callback: any, thisArg: unknown | null = null) {
  // forEach has no way to interrupt execution, short-circuit unless an
  // error is thrown. so we use this:
  each(Object.keys(object), callback, thisArg);
}
