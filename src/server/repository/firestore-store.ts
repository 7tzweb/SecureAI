import { FieldPath } from "firebase-admin/firestore";
import {
  type PaymentRecord,
  type ScanEvent,
  type ScanFinding,
  type ScanRecord,
  type UserRecord,
} from "@/lib/types";
import { forbidden, notFound } from "@/server/api/errors";
import { getFirebaseAdminDb } from "@/server/firebase-admin";
import { type Repository } from "@/server/repository/types";
import { accountEmailsMatch, normalizeAccountEmail } from "@/server/users/account";

function normalizeUserRecord(user: UserRecord): UserRecord {
  return {
    ...user,
    normalizedEmail: normalizeAccountEmail(user.email),
    purchasedScans: user.purchasedScans ?? user.purchasedScanCredits ?? 0,
  };
}

function uniqueUsers(users: UserRecord[]) {
  const byUid = new Map<string, UserRecord>();
  users.forEach((user) => {
    byUid.set(user.uid, normalizeUserRecord(user));
  });
  return [...byUid.values()];
}

function uniqueScans(scans: ScanRecord[]) {
  const byId = new Map<string, ScanRecord>();
  scans.forEach((scan) => {
    byId.set(scan.id, scan);
  });
  return [...byId.values()].sort((left, right) => right.createdAt.localeCompare(left.createdAt));
}

function chunks<T>(items: T[], size: number) {
  const result: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    result.push(items.slice(index, index + size));
  }
  return result;
}

function stripUndefinedForFirestore<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) =>
      typeof item === "undefined" ? null : stripUndefinedForFirestore(item),
    ) as T;
  }

  if (!value || typeof value !== "object") {
    return value;
  }

  const sanitized: Record<string, unknown> = {};
  Object.entries(value as Record<string, unknown>).forEach(([key, entry]) => {
    if (typeof entry !== "undefined") {
      sanitized[key] = stripUndefinedForFirestore(entry);
    }
  });

  return sanitized as T;
}

export function createFirestoreRepository(): Repository {
  const db = getFirebaseAdminDb();

  async function listUsersByEmail(email: string) {
    const normalizedEmail = normalizeAccountEmail(email);
    if (!normalizedEmail) {
      return [];
    }

    const [normalizedSnapshot, legacySnapshot] = await Promise.all([
      db.collection("users").where("normalizedEmail", "==", normalizedEmail).get(),
      db.collection("users").where("email", "==", normalizedEmail).get(),
    ]);

    return uniqueUsers(
      [...normalizedSnapshot.docs, ...legacySnapshot.docs].map((doc) => doc.data() as UserRecord),
    );
  }

  async function accountUserIds(userId: string, userEmail?: string | null) {
    const ids = new Set<string>([userId]);
    const normalizedEmail = normalizeAccountEmail(userEmail);
    if (normalizedEmail) {
      const users = await listUsersByEmail(normalizedEmail);
      users.forEach((user) => ids.add(user.uid));
    }
    return [...ids];
  }

  async function scanBelongsToAccount(
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

    if (!scan.createdByUserId) {
      return false;
    }

    const ownerSnapshot = await db.collection("users").doc(scan.createdByUserId).get();
    if (!ownerSnapshot.exists) {
      return false;
    }

    const owner = ownerSnapshot.data() as UserRecord;
    return accountEmailsMatch(owner.email, normalizedEmail);
  }

  return {
    async createScan(scan) {
      await db.collection("scans").doc(scan.id).set(stripUndefinedForFirestore(scan));
      return scan;
    },

    async getScan(scanId) {
      const snapshot = await db.collection("scans").doc(scanId).get();
      return snapshot.exists ? (snapshot.data() as ScanRecord) : null;
    },

    async updateScan(scanId, patch) {
      const ref = db.collection("scans").doc(scanId);
      const snapshot = await ref.get();
      if (!snapshot.exists) {
        throw notFound("Scan not found.");
      }

      const existing = snapshot.data() as ScanRecord;
      const next = { ...existing, ...patch };
      await ref.set(stripUndefinedForFirestore(next), { merge: true });
      return next;
    },

    async mutateScan(scanId, mutator) {
      const ref = db.collection("scans").doc(scanId);

      return db.runTransaction(async (transaction) => {
        const snapshot = await transaction.get(ref);
        if (!snapshot.exists) {
          throw notFound("Scan not found.");
        }

        const current = snapshot.data() as ScanRecord;
        const next = mutator(current);
        transaction.set(ref, stripUndefinedForFirestore(next), { merge: true });
        return next;
      });
    },

    async replaceFindingsForCategory(scanId, category, findings) {
      const findingsRef = db.collection("scans").doc(scanId).collection("findings");
      const current = await findingsRef.where("category", "==", category).get();
      const batch = db.batch();

      current.docs.forEach((doc) => batch.delete(doc.ref));
      findings.forEach((finding) => {
        batch.set(findingsRef.doc(finding.id), stripUndefinedForFirestore(finding));
      });

      await batch.commit();
    },

    async listFindings(scanId, category) {
      const findingsRef = db.collection("scans").doc(scanId).collection("findings");
      const snapshot = category
        ? await findingsRef.where("category", "==", category).get()
        : await findingsRef.get();

      return snapshot.docs.map((doc) => doc.data() as ScanFinding);
    },

    async addEvent(scanId, event) {
      await db
        .collection("scans")
        .doc(scanId)
        .collection("events")
        .doc(event.id)
        .set(stripUndefinedForFirestore(event));
    },

    async listEvents(scanId, limit = 25) {
      const snapshot = await db
        .collection("scans")
        .doc(scanId)
        .collection("events")
        .orderBy("createdAt", "desc")
        .limit(limit)
        .get();

      return snapshot.docs.map((doc) => doc.data() as ScanEvent);
    },

    async listUserScans(userId, userEmail) {
      const userIds = await accountUserIds(userId, userEmail);
      const scanSnapshots = await Promise.all(
        chunks(userIds, 10).map((chunk) =>
          chunk.length === 1
            ? db.collection("scans").where("createdByUserId", "==", chunk[0]).get()
            : db.collection("scans").where("createdByUserId", "in", chunk).get(),
        ),
      );
      const scans = scanSnapshots.flatMap((snapshot) =>
        snapshot.docs.map((doc) => doc.data() as ScanRecord),
      );

      const normalizedEmail = normalizeAccountEmail(userEmail);
      if (normalizedEmail) {
        const emailSnapshot = await db
          .collection("scans")
          .where("createdByUserEmail", "==", normalizedEmail)
          .get();
        scans.push(...emailSnapshot.docs.map((doc) => doc.data() as ScanRecord));
      }

      return uniqueScans(scans);
    },

    async countUserScans(userId, userEmail) {
      const userIds = await accountUserIds(userId, userEmail);
      const scanSnapshots = await Promise.all(
        chunks(userIds, 10).map((chunk) =>
          chunk.length === 1
            ? db.collection("scans").where("createdByUserId", "==", chunk[0]).get()
            : db.collection("scans").where("createdByUserId", "in", chunk).get(),
        ),
      );
      const scanIds = new Set<string>();
      scanSnapshots.forEach((snapshot) => {
        snapshot.docs.forEach((doc) => scanIds.add(doc.id));
      });

      const normalizedEmail = normalizeAccountEmail(userEmail);
      if (normalizedEmail) {
        const emailSnapshot = await db
          .collection("scans")
          .where("createdByUserEmail", "==", normalizedEmail)
          .get();
        emailSnapshot.docs.forEach((doc) => scanIds.add(doc.id));
      }

      return scanIds.size;
    },

    async countAnonymousScans(anonymousClientId) {
      const snapshot = await db
        .collection("scans")
        .where("anonymousClientId", "==", anonymousClientId)
        .count()
        .get();

      return snapshot.data().count;
    },

    async listRecentScans(limit = 8) {
      const snapshot = await db
        .collection("scans")
        .orderBy("createdAt", "desc")
        .limit(limit)
        .get();

      return snapshot.docs.map((doc) => doc.data() as ScanRecord);
    },

    async claimScan(scanId, userId, userEmail) {
      const ref = db.collection("scans").doc(scanId);
      const snapshot = await ref.get();
      if (!snapshot.exists) {
        throw notFound("Scan not found.");
      }

      const scan = snapshot.data() as ScanRecord;
      if (scan.createdByUserId && !(await scanBelongsToAccount(scan, userId, userEmail))) {
        throw forbidden("This scan belongs to another account.");
      }

      const next = {
        ...scan,
        createdByUserId: userId,
        createdByUserEmail: normalizeAccountEmail(userEmail),
        isAnonymous: false,
        visibility: "private" as const,
      };
      await ref.set(stripUndefinedForFirestore(next), { merge: true });
      return next;
    },

    async unlockScan(scanId, userId, userEmail) {
      const ref = db.collection("scans").doc(scanId);
      const snapshot = await ref.get();
      if (!snapshot.exists) {
        throw notFound("Scan not found.");
      }

      const scan = snapshot.data() as ScanRecord;
      if (!(await scanBelongsToAccount(scan, userId, userEmail))) {
        throw forbidden("Only the scan owner can unlock premium access.");
      }

      const next = {
        ...scan,
        createdByUserId: userId,
        createdByUserEmail: normalizeAccountEmail(userEmail) ?? scan.createdByUserEmail ?? null,
        premiumUnlocked: true,
      };
      await ref.set(stripUndefinedForFirestore(next), { merge: true });
      return next;
    },

    async upsertUser(user) {
      const next = normalizeUserRecord(user);
      await db
        .collection("users")
        .doc(user.uid)
        .set(stripUndefinedForFirestore(next), { merge: true });
      return next;
    },

    async getUser(uid) {
      const snapshot = await db.collection("users").doc(uid).get();
      return snapshot.exists ? normalizeUserRecord(snapshot.data() as UserRecord) : null;
    },

    listUsersByEmail,

    async updateUserEntitlement(uid, subscriptionStatus, entitlementLevel, stripeCustomerId = null) {
      const ref = db.collection("users").doc(uid);
      const snapshot = await ref.get();
      if (!snapshot.exists) {
        throw notFound("User not found.");
      }

      const user = normalizeUserRecord(snapshot.data() as UserRecord);
      const next = normalizeUserRecord({
        ...user,
        subscriptionStatus,
        entitlementLevel,
        stripeCustomerId: stripeCustomerId ?? user.stripeCustomerId,
      });
      await ref.set(stripUndefinedForFirestore(next), { merge: true });
      return next;
    },

    async addUserScans(uid, scans, userEmail) {
      const ref = db.collection("users").doc(uid);

      return db.runTransaction(async (transaction) => {
        const snapshot = await transaction.get(ref);
        if (!snapshot.exists) {
          throw notFound("User not found.");
        }

        const user = normalizeUserRecord(snapshot.data() as UserRecord);
        const next = normalizeUserRecord({
          ...user,
          email: user.email ?? normalizeAccountEmail(userEmail),
          purchasedScans: (user.purchasedScans ?? user.purchasedScanCredits ?? 0) + scans,
        });
        transaction.set(ref, stripUndefinedForFirestore(next), { merge: true });
        return next;
      });
    },

    async upsertPayment(payment) {
      await db
        .collection("payments")
        .doc(payment.checkoutSessionId)
        .set(stripUndefinedForFirestore(payment), { merge: true });
      return payment;
    },

    async completeScanPayment(payment) {
      const paymentRef = db.collection("payments").doc(payment.checkoutSessionId);
      const userRef = db.collection("users").doc(payment.userId);

      return db.runTransaction(async (transaction) => {
        const [paymentSnapshot, userSnapshot] = await Promise.all([
          transaction.get(paymentRef),
          transaction.get(userRef),
        ]);
        const existingPayment = paymentSnapshot.exists
          ? (paymentSnapshot.data() as PaymentRecord)
          : null;
        const alreadyPaid = existingPayment?.paymentStatus === "paid";
        const now = payment.updatedAt;
        const nextPayment: PaymentRecord = {
          ...(existingPayment ?? payment),
          ...payment,
          createdAt: existingPayment?.createdAt ?? payment.createdAt,
          paymentStatus: "paid",
          addedToAccountAt:
            existingPayment?.addedToAccountAt ??
            existingPayment?.creditedAt ??
            (alreadyPaid ? existingPayment?.updatedAt ?? now : now),
          updatedAt: now,
        };

        if (!alreadyPaid) {
          if (!userSnapshot.exists) {
            throw notFound("User not found.");
          }

          const user = normalizeUserRecord(userSnapshot.data() as UserRecord);
          const nextUser = normalizeUserRecord({
            ...user,
            email: user.email ?? normalizeAccountEmail(payment.userEmail),
            purchasedScans:
              (user.purchasedScans ?? user.purchasedScanCredits ?? 0) +
              (payment.scansPurchased ?? payment.creditsPurchased ?? 0),
          });
          transaction.set(userRef, stripUndefinedForFirestore(nextUser), { merge: true });
        }

        transaction.set(paymentRef, stripUndefinedForFirestore(nextPayment), { merge: true });
        return nextPayment;
      });
    },

    async getPaymentByCheckoutSessionId(checkoutSessionId) {
      const snapshot = await db.collection("payments").doc(checkoutSessionId).get();
      if (snapshot.exists) {
        return snapshot.data() as PaymentRecord;
      }

      const fallback = await db
        .collection("payments")
        .where(FieldPath.documentId(), "==", checkoutSessionId)
        .limit(1)
        .get();

      return fallback.empty ? null : (fallback.docs[0]?.data() as PaymentRecord);
    },
  };
}
