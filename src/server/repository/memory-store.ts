import {
  type PaymentRecord,
  type ScanEvent,
  type ScanFinding,
  type ScanRecord,
  type UserRecord,
} from "@/lib/types";
import { forbidden, notFound } from "@/server/api/errors";
import { type Repository } from "@/server/repository/types";
import { accountEmailsMatch, normalizeAccountEmail } from "@/server/users/account";

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

function normalizeUserRecord(user: UserRecord): UserRecord {
  return {
    ...user,
    normalizedEmail: normalizeAccountEmail(user.email),
  };
}

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

function listUsersByEmailFromState(state: MemoryState, email: string) {
  const normalizedEmail = normalizeAccountEmail(email);
  if (!normalizedEmail) {
    return [];
  }

  return [...state.users.values()]
    .filter(
      (user) =>
        accountEmailsMatch(user.normalizedEmail, normalizedEmail) ||
        accountEmailsMatch(user.email, normalizedEmail),
    )
    .map(normalizeUserRecord);
}

function accountUserIds(state: MemoryState, userId: string, userEmail?: string | null) {
  const ids = new Set<string>([userId]);
  listUsersByEmailFromState(state, userEmail ?? "").forEach((user) => ids.add(user.uid));
  return ids;
}

function scanBelongsToAccount(
  state: MemoryState,
  scan: ScanRecord,
  userId: string,
  userEmail?: string | null,
) {
  if (scan.createdByUserId === userId) {
    return true;
  }

  const normalizedEmail = normalizeAccountEmail(userEmail);
  if (!normalizedEmail) {
    return false;
  }

  if (accountEmailsMatch(scan.createdByUserEmail, normalizedEmail)) {
    return true;
  }

  const owner = scan.createdByUserId ? state.users.get(scan.createdByUserId) : null;
  return Boolean(owner && accountEmailsMatch(owner.email, normalizedEmail));
}

function listScansForAccount(state: MemoryState, userId: string, userEmail?: string | null) {
  const userIds = accountUserIds(state, userId, userEmail);
  const normalizedEmail = normalizeAccountEmail(userEmail);

  return [...state.scans.values()]
    .filter(
      (scan) =>
        Boolean(scan.createdByUserId && userIds.has(scan.createdByUserId)) ||
        Boolean(normalizedEmail && accountEmailsMatch(scan.createdByUserEmail, normalizedEmail)),
    )
    .sort((left, right) => right.createdAt.localeCompare(left.createdAt));
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

    async listUserScans(userId, userEmail) {
      return listScansForAccount(state, userId, userEmail);
    },

    async countUserScans(userId, userEmail) {
      return listScansForAccount(state, userId, userEmail).length;
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

    async claimScan(scanId, userId, userEmail) {
      const scan = state.scans.get(scanId);
      if (!scan) {
        throw notFound("Scan not found.");
      }
      if (scan.createdByUserId && !scanBelongsToAccount(state, scan, userId, userEmail)) {
        throw forbidden("This scan belongs to another account.");
      }

      const next = {
        ...scan,
        createdByUserId: userId,
        createdByUserEmail: normalizeAccountEmail(userEmail),
        isAnonymous: false,
        visibility: "private" as const,
      };
      state.scans.set(scanId, next);
      return next;
    },

    async unlockScan(scanId, userId, userEmail) {
      const scan = state.scans.get(scanId);
      if (!scan) {
        throw notFound("Scan not found.");
      }
      if (!scanBelongsToAccount(state, scan, userId, userEmail)) {
        throw forbidden("Only the scan owner can unlock premium access.");
      }

      const next = {
        ...scan,
        createdByUserId: userId,
        createdByUserEmail: normalizeAccountEmail(userEmail) ?? scan.createdByUserEmail ?? null,
        premiumUnlocked: true,
      };
      state.scans.set(scanId, next);
      return next;
    },

    async upsertUser(user) {
      const next = normalizeUserRecord(user);
      state.users.set(user.uid, next);
      return next;
    },

    async getUser(uid) {
      const user = state.users.get(uid);
      return user ? normalizeUserRecord(user) : null;
    },

    async listUsersByEmail(email) {
      return listUsersByEmailFromState(state, email);
    },

    async updateUserEntitlement(uid, subscriptionStatus, entitlementLevel, stripeCustomerId = null) {
      const user = state.users.get(uid);
      if (!user) {
        throw notFound("User not found.");
      }

      const next: UserRecord = normalizeUserRecord({
        ...user,
        subscriptionStatus,
        entitlementLevel,
        stripeCustomerId: stripeCustomerId ?? user.stripeCustomerId,
      });
      state.users.set(uid, next);
      return next;
    },

    async addUserScanCredits(uid, credits, userEmail) {
      const user = state.users.get(uid);
      if (!user) {
        throw notFound("User not found.");
      }

      const next: UserRecord = normalizeUserRecord({
        ...user,
        email: user.email ?? normalizeAccountEmail(userEmail),
        purchasedScanCredits: (user.purchasedScanCredits ?? 0) + credits,
      });
      state.users.set(uid, next);
      return next;
    },

    async upsertPayment(payment) {
      state.payments.set(payment.checkoutSessionId, payment);
      return payment;
    },

    async completeScanCreditPayment(payment) {
      const existingPayment = state.payments.get(payment.checkoutSessionId) ?? null;
      const alreadyPaid = existingPayment?.paymentStatus === "paid";
      const now = payment.updatedAt;
      const nextPayment: PaymentRecord = {
        ...(existingPayment ?? payment),
        ...payment,
        createdAt: existingPayment?.createdAt ?? payment.createdAt,
        paymentStatus: "paid",
        creditedAt: existingPayment?.creditedAt ?? (alreadyPaid ? existingPayment?.updatedAt ?? now : now),
        updatedAt: now,
      };

      if (!alreadyPaid) {
        const user = state.users.get(payment.userId);
        if (!user) {
          throw notFound("User not found.");
        }

        state.users.set(
          payment.userId,
          normalizeUserRecord({
            ...user,
            email: user.email ?? normalizeAccountEmail(payment.userEmail),
            purchasedScanCredits:
              (user.purchasedScanCredits ?? 0) + (payment.creditsPurchased ?? 0),
          }),
        );
      }

      state.payments.set(payment.checkoutSessionId, nextPayment);
      return nextPayment;
    },

    async getPaymentByCheckoutSessionId(checkoutSessionId) {
      return state.payments.get(checkoutSessionId) ?? null;
    },
  };
}
