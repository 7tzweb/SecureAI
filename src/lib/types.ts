export const categoryKeys = ["security", "seo", "performance"] as const;
export const severityLevels = ["info", "low", "medium", "high", "critical"] as const;
export const findingStatuses = ["pass", "info", "warning", "fail"] as const;
export const findingConfidences = ["confirmed", "likely", "medium", "low", "info"] as const;
export const categoryRunStatuses = ["queued", "running", "completed", "failed"] as const;
export const scanStatuses = [
  "queued",
  "initializing",
  "running",
  "partial-results",
  "analyzing",
  "generating-report",
  "partial",
  "completed",
  "failed",
] as const;
export const scanPhases = [
  "init",
  "fast-baseline",
  "attack-surface",
  "browser-render",
  "active-probes",
  "analysis",
  "report",
] as const;
export const securityFindingCategories = [
  "injection",
  "xss",
  "authentication",
  "authorization",
  "session",
  "headers",
  "cors",
  "exposure",
  "transport",
  "configuration",
  "attack-path",
  "recon",
  "other",
] as const;
export const evidenceTypes = [
  "request-response",
  "browser-execution",
  "dom",
  "console",
  "dialog",
  "network",
  "cookie",
  "storage",
  "token",
  "diff",
  "timing",
  "access-matrix",
  "ownership",
  "attack-path-step",
] as const;

export type CategoryKey = (typeof categoryKeys)[number];
export type Severity = (typeof severityLevels)[number];
export type FindingStatus = (typeof findingStatuses)[number];
export type FindingConfidence = (typeof findingConfidences)[number];
export type CategoryRunStatus = (typeof categoryRunStatuses)[number];
export type ScanStatus = (typeof scanStatuses)[number];
export type ScanPhase = (typeof scanPhases)[number];
export type ScanMode = "Fast" | "Deep" | "Authenticated";
export type SecurityFindingCategory = (typeof securityFindingCategories)[number];
export type EvidenceType = (typeof evidenceTypes)[number];
export type EvidenceStrength = "weak" | "moderate" | "strong" | "exploit-proof";
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

export interface StructuredEvidence {
  type: EvidenceType;
  url?: string;
  method?: string;
  statusBefore?: number | null;
  statusAfter?: number | null;
  parameter?: string;
  payload?: string;
  sanitizedPayload?: string;
  beforeSummary?: string;
  afterSummary?: string;
  responseDiff?: string;
  normalizedBodyHashBefore?: string;
  normalizedBodyHashAfter?: string;
  browserSignal?: string;
  consoleMessage?: string;
  dialogMessage?: string;
  domMarker?: string;
  timingBaselineMs?: number;
  timingTestMs?: number;
  timingControlMs?: number;
  ownerContext?: string;
  attackerContext?: string;
  victimContext?: string;
  leakedFields?: string[];
  notes?: string;
}

export interface ScanRecord {
  id: string;
  target: string;
  normalizedTarget: string;
  targetHostname: string;
  createdByUserId: string | null;
  createdByUserEmail?: string | null;
  anonymousClientId: string | null;
  createdAt: string;
  updatedAt: string;
  status: ScanStatus;
  currentPhase?: ScanPhase;
  partialSummary?: {
    securityScore?: number;
    securityRiskLabel?: string;
    confirmedCount?: number;
    likelyCount?: number;
    warningCount?: number;
    infoCount?: number;
    firstFix?: string;
  };
  phaseTimings?: Array<{
    phase: ScanPhase;
    startedAt: string;
    endedAt?: string;
    durationMs?: number;
    findingsAdded?: number;
    urlsChecked?: number;
    errors?: number;
  }>;
  scanMode?: ScanMode;
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
  findingClass?: SecurityFindingCategory;
  status: FindingStatus;
  severity: Severity;
  computedRiskSeverity?: Severity;
  scoringTags?: string[];
  confidence?: FindingConfidence;
  evidenceStrength?: EvidenceStrength;
  falsePositiveRisk?: "low" | "medium" | "high";
  scoreWeight?: number;
  shortDescription: string;
  whyItMatters: string;
  recommendation: string;
  evidence: ScanFindingEvidence;
  structuredEvidence?: StructuredEvidence[];
  proofSummary?: string;
  affectedUrl?: string;
  affectedParameter?: string;
  affectedMethod?: string;
  exploitabilityScore?: number;
  impactScore?: number;
  exposureScore?: number;
  confidenceScore?: number;
  riskScore?: number;
  priorityLabel?: "Fix immediately" | "High priority" | "Medium priority" | "Low priority";
  publicEndpoint?: boolean;
  authRequired?: boolean;
  dataExposure?: boolean;
  attackPathParticipant?: boolean;
  isFixableVulnerability?: boolean;
  isMetaFinding?: boolean;
  isExploitSupportingEvidence?: boolean;
  capabilitiesGained?: string[];
  requiresCapabilities?: string[];
  falsePositiveNotes?: string;
  fixFirstReason?: string;
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
  normalizedEmail?: string | null;
  displayName: string | null;
  photoURL: string | null;
  createdAt: string;
  lastLoginAt: string;
  roles: string[];
  subscriptionStatus: SubscriptionStatus;
  stripeCustomerId: string | null;
  entitlementLevel: EntitlementLevel;
  purchasedScanCredits?: number;
}

export interface PaymentRecord {
  id: string;
  userId: string;
  userEmail?: string | null;
  scanId: string;
  stripeCustomerId: string | null;
  checkoutSessionId: string;
  paymentStatus: "pending" | "paid" | "failed";
  productKey: string;
  paymentProvider?: "stripe" | "paypal";
  paypalOrderId?: string | null;
  creditsPurchased?: number;
  amountUsd?: number;
  creditedAt?: string | null;
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
  purchasedScanCredits: number;
  totalScanAllowance: number;
  remainingScans: number;
  requiresUpgrade: boolean;
  hasUnlimitedPlan: boolean;
  canCreateScans: boolean;
  upgradePriceUsd: number;
  upgradeScanCredits: number;
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
