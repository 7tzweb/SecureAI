export const categoryKeys = ["security", "seo", "performance"] as const;
export const severityLevels = ["info", "low", "medium", "high", "critical"] as const;
export const findingStatuses = ["pass", "info", "warning", "fail"] as const;
export const categoryRunStatuses = ["queued", "running", "completed", "failed"] as const;
export const scanStatuses = ["queued", "running", "partial", "completed", "failed"] as const;

export type CategoryKey = (typeof categoryKeys)[number];
export type Severity = (typeof severityLevels)[number];
export type FindingStatus = (typeof findingStatuses)[number];
export type CategoryRunStatus = (typeof categoryRunStatuses)[number];
export type ScanStatus = (typeof scanStatuses)[number];
export type SubscriptionStatus = "free" | "premium";
export type EntitlementLevel = "free" | "premium";

export interface CategoryState {
  status: CategoryRunStatus;
  score: number | null;
  findingCount: number;
  updatedAt: string;
  error: string | null;
}

export interface FindingEvidenceLocation {
  label: string;
  selector?: string;
  path?: string;
  url?: string;
  context?: string;
  value?: string;
  attribute?: string;
  note?: string;
}

export interface ScanFindingEvidence {
  checkedUrl?: string;
  expectedLocation?: string;
  summary?: string;
  locations?: FindingEvidenceLocation[];
  [key: string]: unknown;
}

export interface ScanRecord {
  id: string;
  target: string;
  normalizedTarget: string;
  targetHostname: string;
  createdByUserId: string | null;
  createdAt: string;
  updatedAt: string;
  status: ScanStatus;
  progress: number;
  overallScore: number | null;
  securityScore: number | null;
  seoScore: number | null;
  performanceScore: number | null;
  isAnonymous: boolean;
  premiumUnlocked: boolean;
  visibility: "private" | "link";
  latestPhase: string;
  errorSummary: string | null;
  categoryStatus: Record<CategoryKey, CategoryState>;
}

export interface ScanFinding {
  id: string;
  checkKey?: string;
  title: string;
  category: CategoryKey;
  status: FindingStatus;
  severity: Severity;
  scoreWeight?: number;
  shortDescription: string;
  whyItMatters: string;
  recommendation: string;
  evidence: ScanFindingEvidence;
  references: string[];
  premiumOnly: boolean;
  createdAt: string;
  updatedAt: string;
  locked?: boolean;
}

export interface ScanEvent {
  id: string;
  type: "status" | "finding" | "billing" | "auth" | "system";
  message: string;
  phase: string;
  progress: number;
  createdAt: string;
  metadata: Record<string, unknown>;
}

export interface UserRecord {
  uid: string;
  email: string | null;
  displayName: string | null;
  photoURL: string | null;
  createdAt: string;
  lastLoginAt: string;
  roles: string[];
  subscriptionStatus: SubscriptionStatus;
  stripeCustomerId: string | null;
  entitlementLevel: EntitlementLevel;
}

export interface PaymentRecord {
  id: string;
  userId: string;
  scanId: string;
  stripeCustomerId: string | null;
  checkoutSessionId: string;
  paymentStatus: "pending" | "paid" | "failed";
  productKey: string;
  createdAt: string;
  updatedAt: string;
}

export interface SessionUser {
  uid: string;
  email: string | null;
  displayName: string | null;
  photoURL: string | null;
  subscriptionStatus: SubscriptionStatus;
  entitlementLevel: EntitlementLevel;
}

export interface ScanQuotaSummary {
  usedScans: number;
  freeLimit: number;
  remainingScans: number;
  requiresUpgrade: boolean;
  hasUnlimitedPlan: boolean;
  canCreateScans: boolean;
  upgradePriceUsd: number;
}

export interface ScanSummaryResponse {
  scan: ScanRecord;
  viewerCanAccessFixes: boolean;
  session: {
    isAuthenticated: boolean;
    userId: string | null;
  };
}

export interface ScanFindingsResponse {
  findings: ScanFinding[];
  viewerCanAccessFixes: boolean;
}

export interface ScanEventsResponse {
  events: ScanEvent[];
}
