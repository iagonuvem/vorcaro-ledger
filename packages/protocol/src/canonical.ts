export type CanonicalJson =
  | null
  | boolean
  | number
  | bigint
  | string
  | readonly CanonicalJson[]
  | { readonly [key: string]: CanonicalJson | undefined };

export function canonicalize(value: CanonicalJson): string {
  if (value === null) {
    return "null";
  }

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (typeof value === "string") {
    return JSON.stringify(value);
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("JCS cannot encode non-finite numbers");
    }

    if (Object.is(value, -0)) {
      return "0";
    }

    return JSON.stringify(value);
  }

  if (typeof value === "bigint") {
    return value.toString(10);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(",")}]`;
  }

  if (typeof value === "object") {
    const entries = Object.entries(value)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left.localeCompare(right));

    return `{${entries
      .map(([key, item]) => `${JSON.stringify(key)}:${canonicalize(item as CanonicalJson)}`)
      .join(",")}}`;
  }

  throw new TypeError(`JCS cannot encode ${typeof value}`);
}

export function canonicalBytes(value: CanonicalJson): Buffer {
  return Buffer.from(canonicalize(value), "utf8");
}
