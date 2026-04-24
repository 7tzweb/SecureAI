import {
  type CategoryKey,
  type EntitlementLevel,
  type PaymentRecord,
  type ScanEvent,
  type ScanFinding,
  type ScanRecord,
  type SubscriptionStatus,
  type UserRecord,
} from "@/lib/types";

export interface Repository {
  createScan(scan: ScanRecord): Promise<ScanRecord>;
  getScan(scanId: string): Promise<ScanRecord | null>;
  updateScan(scanId: string, patch: Partial<ScanRecord>): Promise<ScanRecord>;
  mutateScan(
    scanId: string,
    mutator: (current: ScanRecord) => ScanRecord,
  ): Promise<ScanRecord>;
  replaceFindingsForCategory(
    scanId: string,
    category: CategoryKey,
    findings: ScanFinding[],
  ): Promise<void>;
  listFindings(scanId: string, category?: CategoryKey): Promise<ScanFinding[]>;
  addEvent(scanId: string, event: ScanEvent): Promise<void>;
  listEvents(scanId: string, limit?: number): Promise<ScanEvent[]>;
  listUserScans(userId: string): Promise<ScanRecord[]>;
  countUserScans(userId: string): Promise<number>;
  listRecentScans(limit?: number): Promise<ScanRecord[]>;
  claimScan(scanId: string, userId: string): Promise<ScanRecord>;
  unlockScan(scanId: string, userId: string): Promise<ScanRecord>;
  upsertUser(user: UserRecord): Promise<UserRecord>;
  getUser(uid: string): Promise<UserRecord | null>;
  updateUserEntitlement(
    uid: string,
    subscriptionStatus: SubscriptionStatus,
    entitlementLevel: EntitlementLevel,
    stripeCustomerId?: string | null,
  ): Promise<UserRecord>;
  upsertPayment(payment: PaymentRecord): Promise<PaymentRecord>;
  getPaymentByCheckoutSessionId(checkoutSessionId: string): Promise<PaymentRecord | null>;
}
