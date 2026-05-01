import {
  type PaymentRecord,
  type ScanEvent,
  type ScanFinding,
  type ScanRecord,
  type UserRecord,
} from "@/lib/types";
import { forbidden, notFound } from "@/server/api/errors";
import { type Repository } from "@/server/repository/types";

type MemoryState = {
  scans: Map<string, ScanRecord>;
  findings: Map<string, ScanFinding[]>;
  events: Map<string, ScanEvent[]>;
  users: Map<string, UserRecord>;
  payments: Map<string, PaymentRecord>;
};

const globalState = globalThis as typeof globalThis & {
  __cyberAuditMemoryStore?: MemoryState;
};

function getState(): MemoryState {
  if (!globalState.__cyberAuditMemoryStore) {
    globalState.__cyberAuditMemoryStore = {
      scans: new Map(),
      findings: new Map(),
      events: new Map(),
      users: new Map(),
      payments: new Map(),
    };
  }

  return globalState.__cyberAuditMemoryStore;
}

export function createMemoryRepository(): Repository {
  const state = getState();

  return {
    async createScan(scan) {
      state.scans.set(scan.id, scan);
      state.findings.set(scan.id, []);
      state.events.set(scan.id, []);
      return scan;
    },

    async getScan(scanId) {
      return state.scans.get(scanId) ?? null;
    },

    async updateScan(scanId, patch) {
      const existing = state.scans.get(scanId);
      if (!existing) {
        throw notFound("Scan not found.");
      }

      const next = { ...existing, ...patch };
      state.scans.set(scanId, next);
      return next;
    },

    async mutateScan(scanId, mutator) {
      const existing = state.scans.get(scanId);
      if (!existing) {
        throw notFound("Scan not found.");
      }

      const next = mutator(existing);
      state.scans.set(scanId, next);
      return next;
    },

    async replaceFindingsForCategory(scanId, category, findings) {
      const existing = state.findings.get(scanId) ?? [];
      const next = existing
        .filter((finding) => finding.category !== category)
        .concat(findings);
      state.findings.set(scanId, next);
    },

    async listFindings(scanId, category) {
      const findings = state.findings.get(scanId) ?? [];
      return category ? findings.filter((finding) => finding.category === category) : findings;
    },

    async addEvent(scanId, event) {
      const events = state.events.get(scanId) ?? [];
      state.events.set(scanId, [event, ...events].slice(0, 100));
    },

    async listEvents(scanId, limit = 25) {
      return (state.events.get(scanId) ?? []).slice(0, limit);
    },

    async listUserScans(userId) {
      return [...state.scans.values()]
        .filter((scan) => scan.createdByUserId === userId)
        .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
    },

    async countUserScans(userId) {
      return [...state.scans.values()].filter((scan) => scan.createdByUserId === userId).length;
    },

    async countAnonymousScans(anonymousClientId) {
      return [...state.scans.values()].filter(
        (scan) => scan.anonymousClientId === anonymousClientId,
      ).length;
    },

    async listRecentScans(limit = 8) {
      return [...state.scans.values()]
        .sort((left, right) => right.createdAt.localeCompare(left.createdAt))
        .slice(0, limit);
    },

    async claimScan(scanId, userId) {
      const scan = state.scans.get(scanId);
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
      state.scans.set(scanId, next);
      return next;
    },

    async unlockScan(scanId, userId) {
      const scan = state.scans.get(scanId);
      if (!scan) {
        throw notFound("Scan not found.");
      }
      if (scan.createdByUserId !== userId) {
        throw forbidden("Only the scan owner can unlock premium access.");
      }

      const next = { ...scan, premiumUnlocked: true };
      state.scans.set(scanId, next);
      return next;
    },

    async upsertUser(user) {
      state.users.set(user.uid, user);
      return user;
    },

    async getUser(uid) {
      return state.users.get(uid) ?? null;
    },

    async updateUserEntitlement(uid, subscriptionStatus, entitlementLevel, stripeCustomerId = null) {
      const user = state.users.get(uid);
      if (!user) {
        throw notFound("User not found.");
      }

      const next: UserRecord = {
        ...user,
        subscriptionStatus,
        entitlementLevel,
        stripeCustomerId: stripeCustomerId ?? user.stripeCustomerId,
      };
      state.users.set(uid, next);
      return next;
    },

    async addUserScanCredits(uid, credits) {
      const user = state.users.get(uid);
      if (!user) {
        throw notFound("User not found.");
      }

      const next: UserRecord = {
        ...user,
        purchasedScanCredits: (user.purchasedScanCredits ?? 0) + credits,
      };
      state.users.set(uid, next);
      return next;
    },

    async upsertPayment(payment) {
      state.payments.set(payment.checkoutSessionId, payment);
      return payment;
    },

    async getPaymentByCheckoutSessionId(checkoutSessionId) {
      return state.payments.get(checkoutSessionId) ?? null;
    },
  };
}
