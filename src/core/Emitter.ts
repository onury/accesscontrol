// own modules
import type {
  AccessControlEventName,
  AccessControlEventPayload,
  EventListener
} from '../types/index.js';

/**
 * Tiny internal event emitter — no Node `EventEmitter` dependency, so it
 * is ESM/browser-safe and keeps the single-dep footprint.
 *
 * Guarantees:
 * - **Zero overhead when no listener** — callers gate on {@link Emitter#has}
 *   before building a payload.
 * - **Observational only** — listeners cannot veto or alter a decision.
 * - **Fire-and-forget** — listeners are not awaited and a throwing listener is
 *   isolated (caught), so it can never break a check.
 * @internal
 */
export class Emitter {
  private readonly _listeners = new Map<AccessControlEventName, Set<EventListener>>();

  /** Whether at least one listener is registered for `name`. */
  has(name: AccessControlEventName): boolean {
    const set = this._listeners.get(name);
    return set !== undefined && set.size > 0;
  }

  /** Registers a listener for `name`. */
  on(name: AccessControlEventName, listener: EventListener): void {
    let set = this._listeners.get(name);
    if (!set) {
      set = new Set();
      this._listeners.set(name, set);
    }
    set.add(listener);
  }

  /** Registers a one-shot listener that removes itself after the first call. */
  once(name: AccessControlEventName, listener: EventListener): void {
    const wrapper: EventListener = (event) => {
      this.off(name, wrapper);
      listener(event);
    };
    this.on(name, wrapper);
  }

  /**
   * Removes a specific listener, or — when `listener` is omitted — all listeners
   * for `name`.
   */
  off(name: AccessControlEventName, listener?: EventListener): void {
    const set = this._listeners.get(name);
    if (!set) return;
    if (listener) set.delete(listener);
    else set.clear();
  }

  /**
   * Emits `event` to every listener for its `name`. A throwing listener is
   * caught and isolated so it never affects the caller or sibling listeners.
   */
  emit(name: AccessControlEventName, event: AccessControlEventPayload): void {
    const set = this._listeners.get(name);
    if (!set || set.size === 0) return;
    // copy so a listener mutating the set during dispatch can't disrupt iteration
    for (const listener of [...set]) {
      try {
        listener(event);
      } catch {
        // observational + fire-and-forget: a faulty listener never breaks AC.
      }
    }
  }
}
