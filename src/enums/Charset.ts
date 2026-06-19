/**
 * Allowed character set for consumer-supplied names (roles, resources, actions,
 * groups, categories). Selected via `engine.charset`.
 *
 * Regardless of this setting, the structural characters (`/`, `:`, `$`, `*`,
 * `!`) and whitespace are always rejected (they drive possession, groups, the
 * `$extend` keyword and attribute globs), and the reserved prototype-pollution
 * names (`__proto__`, `prototype`, `constructor`) are always rejected.
 *
 */
export enum Charset {
  /**
   * ASCII letters, digits, `_` and `-` only (`[A-Za-z0-9_-]`). **Default.**
   * Recommended: it rules out Unicode homograph attacks (visually identical
   * names with different code points).
   */
  ASCII = 'ascii',
  /**
   * Unicode letters/digits plus `_` and `-` (`[\p{L}\p{N}_-]`, `u` flag).
   * Enables internationalized names (CJK, Cyrillic, accented, …).
   *
   * ⚠️ Homograph risk: distinct code points can render identically — e.g.
   * `аdmin` (Cyrillic `а`) is a *different* name from `admin` (Latin `a`). If you
   * enable this, NFC-normalize names before passing them in and consider
   * restricting to a single script. The library does not normalize for you.
   */
  UNICODE = 'unicode'
}
