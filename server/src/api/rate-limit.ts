import type { Request, RequestHandler } from "express";

export type RateLimitOptions = {
  readonly capacity: number;
  readonly refillPerSecond: number;
  readonly key: (request: Request) => string;
  readonly now?: () => number;
};

type Bucket = {
  tokens: number;
  updatedAt: number;
};

export function createTokenBucketMiddleware(options: RateLimitOptions): RequestHandler {
  const buckets = new Map<string, Bucket>();
  const now = options.now ?? (() => Date.now());

  return (request, response, next) => {
    const key = options.key(request);
    const currentTime = now();
    const existing = buckets.get(key) ?? { tokens: options.capacity, updatedAt: currentTime };
    const elapsedSeconds = Math.max(0, (currentTime - existing.updatedAt) / 1000);
    const tokens = Math.min(options.capacity, existing.tokens + elapsedSeconds * options.refillPerSecond);

    if (tokens < 1) {
      buckets.set(key, { tokens, updatedAt: currentTime });
      response.setHeader("Retry-After", "1");
      response.status(429).type("application/json").send('{"error_code":"POLICY_DENIED"}');
      return;
    }

    buckets.set(key, { tokens: tokens - 1, updatedAt: currentTime });
    next();
  };
}
