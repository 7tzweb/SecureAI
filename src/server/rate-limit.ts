import { tooManyRequests } from "@/server/api/errors";

type BucketName = "create-scan" | "claim-scan" | "checkout";

type BucketRule = {
  windowMs: number;
  limit: number;
};

const rules: Record<BucketName, BucketRule> = {
  "create-scan": { windowMs: 60_000, limit: 10 },
  "claim-scan": { windowMs: 60_000, limit: 20 },
  checkout: { windowMs: 60_000, limit: 10 },
};

type Entry = {
  count: number;
  resetAt: number;
};

const globalState = globalThis as typeof globalThis & {
  __cyberAuditRateLimit?: Map<string, Entry>;
};

function getState() {
  if (!globalState.__cyberAuditRateLimit) {
    globalState.__cyberAuditRateLimit = new Map();
  }

  return globalState.__cyberAuditRateLimit;
}

export function assertRateLimit(bucket: BucketName, identifier: string) {
  const state = getState();
  const rule = rules[bucket];
  const key = `${bucket}:${identifier}`;
  const now = Date.now();
  const current = state.get(key);

  if (!current || current.resetAt <= now) {
    state.set(key, {
      count: 1,
      resetAt: now + rule.windowMs,
    });
    return;
  }

  if (current.count >= rule.limit) {
    throw tooManyRequests("Rate limit exceeded. Please wait before trying again.");
  }

  current.count += 1;
  state.set(key, current);
}
