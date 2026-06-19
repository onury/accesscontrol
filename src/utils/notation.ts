// dep modules
import { Notation } from 'notation';
// own modules
import type { UnknownObject } from '../types/index.js';

// ----------------------
// NOTATION/GLOB UTILS
// ----------------------

/**
 * Deep clones the source object while filtering its properties by the
 * given attributes (glob notations). Includes all matched properties and
 * removes the rest.
 * @param object - Object to be filtered.
 * @param attributes - Array of glob notations.
 */
export function filter(object: UnknownObject, attributes: string[]): UnknownObject {
  if (!Array.isArray(attributes) || attributes.length === 0) {
    return {};
  }
  const notation = new Notation(object);
  return notation.filter(attributes).value as UnknownObject;
}

/**
 * Deep clones the source array of objects or a single object while
 * filtering their properties by the given attributes (glob notations).
 * Includes all matched properties and removes the rest of each object in
 * the array.
 * @param data - Array of objects or single object to be filtered.
 * @param attributes - Array of glob notations.
 */
export function filterAll(
  data: UnknownObject | UnknownObject[],
  attributes: string[]
): UnknownObject | UnknownObject[] {
  if (!Array.isArray(data)) {
    return filter(data, attributes);
  }
  return data.map((o: UnknownObject) => {
    return filter(o, attributes);
  });
}
