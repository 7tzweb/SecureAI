import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  type PaymentRecord,
  type ScanEvent,
  type ScanFinding,
  type ScanRecord,
  type UserRecord,
} from "@/lib/types";
import { forbidden, notFound } from "@/server/api/errors";
import { type Repository } from "@/server/repository/types";

type StorePayload = {
  scans: Record<string, ScanRecord>;
  findings: Record<string, ScanFinding[]>;
  events: Record<string, ScanEvent[]>;
  users: Record<string, UserRecord>;
  payments: Record<string, PaymentRecord>;
};

const storeDirectory = path.join(process.cwd(), ".cyberaudit");
const storeFilePath = path.join(storeDirectory, "runtime-store.json");

const globalState = globalThis as typeof globalThis & {
  __cyberAuditFileStoreLock?: Promise<void>;
  __cyberAuditMemoryStore?: {
    scans: Map<string, ScanRecord>;
    findings: Map<string, ScanFinding[]>;
    events: Map<string, ScanEvent[]>;
    users: Map<string, UserRecord>;
    payments: Map<string, PaymentRecord>;
  };
};

function emptyStore(): StorePayload {
  return {
    scans: {},
    findings: {},
    events: {},
    users: {},
    payments: {},
  };
}

function seedFromMemoryStore(): StorePayload | null {
  const memory = globalState.__cyberAuditMemoryStore;
  if (!memory) {
    return null;
  }

  return {
    scans: Object.fromEntries(memory.scans.entries()),
    findings: Object.fromEntries(memory.findings.entries()),
    events: Object.fromEntries(memory.events.entries()),
    users: Object.fromEntries(memory.users.entries()),
    payments: Object.fromEntries(memory.payments.entries()),
  };
}

async function ensureStoreFile() {
  await mkdir(storeDirectory, { recursive: true });

  try {
    await readFile(storeFilePath, "utf8");
  } catch {
    const seeded = seedFromMemoryStore() ?? emptyStore();
    await writeFile(storeFilePath, JSON.stringify(seeded, null, 2), "utf8");
  }
}

async function readStore() {
  await ensureStoreFile();
  const raw = await readFile(storeFilePath, "utf8");
  return JSON.parse(raw) as StorePayload;
}

async function writeStore(payload: StorePayload) {
  await writeFile(storeFilePath, JSON.stringify(payload, null, 2), "utf8");
}

function withStoreLock<T>(operation: () => Promise<T>): Promise<T> {
  const previous = globalState.__cyberAuditFileStoreLock ?? Promise.resolve();
  let release!: () => void;
  const nextLock = new Promise<void>((resolve) => {
    release = resolve;
  });

  globalState.__cyberAuditFileStoreLock = previous.then(() => nextLock);

  return previous
    .then(operation)
    .finally(() => {
      release();
    });
}

export function createFileRepository(): Repository {
  return {
    async createScan(scan) {
      return withStoreLock(async () => {
        const store = await readStore();
        store.scans[scan.id] = scan;
        store.findings[scan.id] = [];
        store.events[scan.id] = [];
        await writeStore(store);
        return scan;
      });
    },

    async getScan(scanId) {
      return withStoreLock(async () => {
        const store = await readStore();
        return store.scans[scanId] ?? null;
      });
    },

    async updateScan(scanId, patch) {
      return withStoreLock(async () => {
        const store = await readStore();
        const existing = store.scans[scanId];
        if (!existing) {
          throw notFound("Scan not found.");
        }

        const next = { ...existing, ...patch };
        store.scans[scanId] = next;
        await writeStore(store);
        return next;
      });
    },

    async mutateScan(scanId, mutator) {
      return withStoreLock(async () => {
        const store = await readStore();
        const existing = store.scans[scanId];
        if (!existing) {
          throw notFound("Scan not found.");
        }

        const next = mutator(existing);
        store.scans[scanId] = next;
        await writeStore(store);
        return next;
      });
    },

    async replaceFindingsForCategory(scanId, category, findings) {
      return withStoreLock(async () => {
        const store = await readStore();
        const existing = store.findings[scanId] ?? [];
        store.findings[scanId] = existing
          .filter((finding) => finding.category !== category)
          .concat(findings);
        await writeStore(store);
      });
    },

    async listFindings(scanId, category) {
      return withStoreLock(async () => {
        const store = await readStore();
        const findings = store.findings[scanId] ?? [];
        return category
          ? findings.filter((finding) => finding.category === category)
          : findings;
      });
    },

    async addEvent(scanId, event) {
      return withStoreLock(async () => {
        const store = await readStore();
        const events = store.events[scanId] ?? [];
        store.events[scanId] = [event, ...events].slice(0, 100);
        await writeStore(store);
      });
    },

    async listEvents(scanId, limit = 25) {
      return withStoreLock(async () => {
        const store = await readStore();
        return (store.events[scanId] ?? []).slice(0, limit);
      });
    },

    async listUserScans(userId) {
      return withStoreLock(async () => {
        const store = await readStore();
        return Object.values(store.scans)
          .filter((scan) => scan.createdByUserId === userId)
          .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
      });
    },

    async countUserScans(userId) {
      return withStoreLock(async () => {
        const store = await readStore();
        return Object.values(store.scans).filter((scan) => scan.createdByUserId === userId).length;
      });
    },

    async listRecentScans(limit = 8) {
      return withStoreLock(async () => {
        const store = await readStore();
        return Object.values(store.scans)
          .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
          .slice(0, limit);
      });
    },

    async claimScan(scanId, userId) {
      return withStoreLock(async () => {
        const store = await readStore();
        const scan = store.scans[scanId];
        if (!scan) {
          throw notFound("Scan not found.");
        }
        if (scan.createdByUserId && scan.createdByUserId !== userId) {
          throw forbidden("This scan belongs to another account.");
        }

        const next = {
          ...scan,
          createdByUserId: userId,
          isAnonymous: false,
          visibility: "private" as const,
        };
        store.scans[scanId] = next;
        await writeStore(store);
        return next;
      });
    },

    async unlockScan(scanId, userId) {
      return withStoreLock(async () => {
        const store = await readStore();
        const scan = store.scans[scanId];
        if (!scan) {
          throw notFound("Scan not found.");
        }
        if (scan.createdByUserId !== userId) {
          throw forbidden("Only the scan owner can unlock premium access.");
        }

        const next = { ...scan, premiumUnlocked: true };
        store.scans[scanId] = next;
        await writeStore(store);
        return next;
      });
    },

    async upsertUser(user) {
      return withStoreLock(async () => {
        const store = await readStore();
        store.users[user.uid] = user;
        await writeStore(store);
        return user;
      });
    },

    async getUser(uid) {
      return withStoreLock(async () => {
        const store = await readStore();
        return store.users[uid] ?? null;
      });
    },

    async updateUserEntitlement(uid, subscriptionStatus, entitlementLevel, stripeCustomerId = null) {
      return withStoreLock(async () => {
        const store = await readStore();
        const user = store.users[uid];
        if (!user) {
          throw notFound("User not found.");
        }

        const next: UserRecord = {
          ...user,
          subscriptionStatus,
          entitlementLevel,
          stripeCustomerId: stripeCustomerId ?? user.stripeCustomerId,
        };
        store.users[uid] = next;
        await writeStore(store);
        return next;
      });
    },

    async upsertPayment(payment) {
      return withStoreLock(async () => {
        const store = await readStore();
        store.payments[payment.checkoutSessionId] = payment;
        await writeStore(store);
        return payment;
      });
    },

    async getPaymentByCheckoutSessionId(checkoutSessionId) {
      return withStoreLock(async () => {
        const store = await readStore();
        return store.payments[checkoutSessionId] ?? null;
      });
    },
  };
}
