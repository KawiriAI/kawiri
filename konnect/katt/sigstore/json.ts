/**
 * JSON Canonicalization Scheme (JCS) — RFC 8785.
 * Deterministic JSON serialization: sorted object keys, maintained array order.
 * Required for Rekor SET verification.
 */
export function canonicalize(obj: unknown): string {
  if (obj === null || obj === undefined) {
    return "null";
  }

  if (typeof obj === "boolean" || typeof obj === "number") {
    return JSON.stringify(obj);
  }

  if (typeof obj === "string") {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    const items = obj.map((item) => canonicalize(item));
    return `[${items.join(",")}]`;
  }

  if (typeof obj === "object") {
    const keys = Object.keys(obj as Record<string, unknown>).sort();
    const pairs = keys
      .map((key) => {
        const value = (obj as Record<string, unknown>)[key];
        if (value === undefined) return "";
        return `${JSON.stringify(key)}:${canonicalize(value)}`;
      })
      .filter((p) => p !== "");
    return `{${pairs.join(",")}}`;
  }

  return JSON.stringify(obj);
}
