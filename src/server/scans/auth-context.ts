import "server-only";

export type ScanAuthContext = {
  authCookieHeader?: string | null;
  secondaryAuthCookieHeader?: string | null;
};

const globalState = globalThis as typeof globalThis & {
  __fixnxScanAuthContexts?: Map<string, { expiresAt: number; context: ScanAuthContext }>;
};

function getStore() {
  if (!globalState.__fixnxScanAuthContexts) {
    globalState.__fixnxScanAuthContexts = new Map();
  }

  return globalState.__fixnxScanAuthContexts;
}

export function setScanAuthContext(scanId: string, context: ScanAuthContext) {
  if (!context.authCookieHeader && !context.secondaryAuthCookieHeader) {
    return;
  }

  getStore().set(scanId, {
    expiresAt: Date.now() + 30 * 60 * 1_000,
    context,
  });
}

export function getScanAuthContext(scanId: string): ScanAuthContext {
  const store = getStore();
  const entry = store.get(scanId);
  if (!entry) {
    return {};
  }

  if (entry.expiresAt <= Date.now()) {
    store.delete(scanId);
    return {};
  }

  return entry.context;
}
