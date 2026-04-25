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

export function createFirestoreRepository(): Repository {
  const db = getFirebaseAdminDb();

  return {
    async createScan(scan) {
      await db.collection("scans").doc(scan.id).set(scan);
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
      await ref.set(next, { merge: true });
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
        transaction.set(ref, next, { merge: true });
        return next;
      });
    },

    async replaceFindingsForCategory(scanId, category, findings) {
      const findingsRef = db.collection("scans").doc(scanId).collection("findings");
      const current = await findingsRef.where("category", "==", category).get();
      const batch = db.batch();

      current.docs.forEach((doc) => batch.delete(doc.ref));
      findings.forEach((finding) => {
        batch.set(findingsRef.doc(finding.id), finding);
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
      await db.collection("scans").doc(scanId).collection("events").doc(event.id).set(event);
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

    async listUserScans(userId) {
      const snapshot = await db
        .collection("scans")
        .where("createdByUserId", "==", userId)
        .orderBy("createdAt", "desc")
        .get();

      return snapshot.docs.map((doc) => doc.data() as ScanRecord);
    },

    async countUserScans(userId) {
      const snapshot = await db
        .collection("scans")
        .where("createdByUserId", "==", userId)
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

    async claimScan(scanId, userId) {
      const ref = db.collection("scans").doc(scanId);
      const snapshot = await ref.get();
      if (!snapshot.exists) {
        throw notFound("Scan not found.");
      }

      const scan = snapshot.data() as ScanRecord;
      if (scan.createdByUserId && scan.createdByUserId !== userId) {
        throw forbidden("This scan belongs to another account.");
      }

      const next = {
        ...scan,
        createdByUserId: userId,
        isAnonymous: false,
        visibility: "private" as const,
      };
      await ref.set(next, { merge: true });
      return next;
    },

    async unlockScan(scanId, userId) {
      const ref = db.collection("scans").doc(scanId);
      const snapshot = await ref.get();
      if (!snapshot.exists) {
        throw notFound("Scan not found.");
      }

      const scan = snapshot.data() as ScanRecord;
      if (scan.createdByUserId !== userId) {
        throw forbidden("Only the scan owner can unlock premium access.");
      }

      const next = { ...scan, premiumUnlocked: true };
      await ref.set(next, { merge: true });
      return next;
    },

    async upsertUser(user) {
      await db.collection("users").doc(user.uid).set(user, { merge: true });
      return user;
    },

    async getUser(uid) {
      const snapshot = await db.collection("users").doc(uid).get();
      return snapshot.exists ? (snapshot.data() as UserRecord) : null;
    },

    async updateUserEntitlement(uid, subscriptionStatus, entitlementLevel, stripeCustomerId = null) {
      const ref = db.collection("users").doc(uid);
      const snapshot = await ref.get();
      if (!snapshot.exists) {
        throw notFound("User not found.");
      }

      const user = snapshot.data() as UserRecord;
      const next = {
        ...user,
        subscriptionStatus,
        entitlementLevel,
        stripeCustomerId: stripeCustomerId ?? user.stripeCustomerId,
      };
      await ref.set(next, { merge: true });
      return next;
    },

    async addUserScanCredits(uid, credits) {
      const ref = db.collection("users").doc(uid);

      return db.runTransaction(async (transaction) => {
        const snapshot = await transaction.get(ref);
        if (!snapshot.exists) {
          throw notFound("User not found.");
        }

        const user = snapshot.data() as UserRecord;
        const next = {
          ...user,
          purchasedScanCredits: (user.purchasedScanCredits ?? 0) + credits,
        };
        transaction.set(ref, next, { merge: true });
        return next;
      });
    },

    async upsertPayment(payment) {
      await db.collection("payments").doc(payment.checkoutSessionId).set(payment, { merge: true });
      return payment;
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
