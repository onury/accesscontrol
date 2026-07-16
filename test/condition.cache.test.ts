/**
 *  Test Suite: the `during` parse cache, from a fresh module state.
 *  Runs in its own file so the module-level cache starts empty — the eviction
 *  guard's exact boundary is only observable from a known cache size.
 */

import { getDTRExp } from '../src/utils/index.js';

/** Distinct valid one-minute windows: T0000:0001, T0001:0002, … */
function expr(i: number): string {
  const pad = (m: number) =>
    `${String(Math.floor(m / 60)).padStart(2, '0')}${String(m % 60).padStart(2, '0')}`;
  return `T${pad(i)}:${pad(i + 1)}`;
}

describe('Test Suite: during parse cache (fresh module state)', () => {
  // shared across the two tests below (they run in order, same module state)
  let first: unknown;

  test('entries below capacity are never evicted (identity-stable at exactly MAX)', () => {
    // the cache is empty here; fill it to exactly MAX_DTREXP_CACHE (500).
    first = getDTRExp(expr(0));
    for (let i = 1; i < 500; i++) getDTRExp(expr(i));
    // no insertion has exceeded capacity — the first entry must still be
    // cached (an eager-eviction mutant would have dropped it long ago).
    expect(getDTRExp(expr(0))).toBe(first);
  });

  test('the insertion that exceeds capacity evicts exactly the oldest entry', () => {
    // cache is full (500, expr(0) oldest); one more insertion evicts expr(0).
    const second = getDTRExp(expr(1)); // a hit — does not reorder the cache
    getDTRExp(expr(500));
    expect(getDTRExp(expr(1))).toBe(second); // second-oldest untouched
    expect(getDTRExp(expr(0))).not.toBe(first); // evicted → re-parsed instance
  });
});
