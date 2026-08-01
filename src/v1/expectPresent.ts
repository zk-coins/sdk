/**
 * Fail-closed presence check: throw if the value is missing, otherwise return it.
 *
 * No silent defaults — the value is either present or the call throws.
 */

export function expectPresent<T>(value: T | null | undefined, message: string): T {
  if (value === null || value === undefined) {
    throw new Error(message);
  }
  return value;
}
