import assert from "node:assert/strict";
import type { ScanFinding } from "../src/lib/types";
import { normalizeFinding } from "../src/security/findings";
import { buildAttackPaths } from "../src/security/analysis/attackPathBuilder";
import { buildReportSummary } from "../src/security/reportSummary";

type FindingInput = Partial<ScanFinding> &
  Pick<ScanFinding, "id" | "checkKey" | "title" | "status" | "severity">;

const now = new Date("2026-05-04T00:00:00.000Z").toISOString();

function finding(input: FindingInput) {
  return normalizeFinding({
    category: "security",
    confidence: input.status === "pass" || input.status === "info" ? "info" : "likely",
    shortDescription: "Synthetic regression finding.",
    whyItMatters: "Used to verify report prioritization behavior.",
    recommendation: "Review the affected control.",
    evidence: {},
    references: [],
    premiumOnly: false,
    createdAt: now,
    updatedAt: now,
    ...input,
  } satisfies ScanFinding);
}

function report(findings: ScanFinding[]) {
  const attackPaths = buildAttackPaths(findings);
  return buildReportSummary({
    target: "https://example.test",
    scanMode: "Fast",
    generatedAt: now,
    findings,
    attackPaths,
    attackSurface: {
      publicApis: 0,
      sensitiveEndpoints: 0,
      missingHeaders: findings.filter((entry) => /header|csp|hsts|frame|referrer/i.test(`${entry.checkKey} ${entry.title}`)).length,
      crawledPages: 12,
      discoveredEndpoints: 4,
      testedParameters: 5,
      activeProbesExecuted: 12,
      scanDurationMs: 12_000,
      scanDuration: "12 sec",
    },
  });
}

const googleLike = report([
  finding({
    id: "security-browser-rendered-crawl-coverage",
    checkKey: "browser-rendered-crawl-coverage",
    title: "Browser-rendered crawl coverage",
    status: "pass",
    severity: "info",
    evidence: { checkedUrl: "https://google.example", rendered: true },
  }),
  finding({
    id: "security-active-xss-payload-reflection",
    checkKey: "active-xss-payload-reflection",
    title: "Active XSS exploit probe",
    status: "pass",
    severity: "info",
    evidence: { checkedUrl: "https://google.example/search?q=test", confidence: "not-detected" },
  }),
  finding({
    id: "security-reflected-input-exposure",
    checkKey: "reflected-input-exposure",
    title: "Reflected input exposure",
    status: "warning",
    severity: "medium",
    confidence: "likely",
    evidence: {
      checkedUrl: "https://google.example/search?q=test",
      reflectedParameters: [
        { url: "https://google.example/search?q=a", parameter: "q", context: "text" },
        { url: "https://google.example/search?q=b", parameter: "q", context: "attribute" },
      ],
    },
  }),
  finding({
    id: "security-xss-risk-indicators",
    checkKey: "xss-risk-indicators",
    title: "XSS evidence review",
    status: "warning",
    severity: "medium",
    confidence: "likely",
    evidence: {
      checkedUrl: "https://google.example/search?q=test",
      reflections: [{ url: "https://google.example/search?q=a", parameter: "q", context: "text" }],
      activePayloadReflections: [],
    },
  }),
  finding({
    id: "security-content-security-policy",
    checkKey: "content-security-policy",
    title: "Weak Content-Security-Policy",
    status: "warning",
    severity: "low",
    confidence: "likely",
    evidence: {
      checkedUrl: "https://google.example",
      value: "upgrade-insecure-requests",
      summary: "CSP is present but weak.",
    },
  }),
  finding({
    id: "security-referrer-policy",
    checkKey: "referrer-policy",
    title: "Referrer-Policy",
    status: "warning",
    severity: "low",
    confidence: "likely",
    evidence: { checkedUrl: "https://google.example", summary: "Header hardening note." },
  }),
  finding({
    id: "security-robots-txt-presence",
    checkKey: "robots-txt-presence",
    title: "robots.txt presence",
    status: "warning",
    severity: "low",
    confidence: "likely",
    evidence: {
      checkedUrl: "https://google.example/robots.txt",
      sensitiveDisallowPaths: ["/search", "/account"],
      samples: [
        {
          path: "/account",
          disallowPathSampled: true,
          reachable: true,
          sensitiveDataObserved: false,
        },
      ],
    },
  }),
  finding({
    id: "security-file-upload-risk-indicators",
    checkKey: "file-upload-risk-indicators",
    title: "File upload risk indicators",
    status: "info",
    severity: "info",
    evidence: { checkedUrl: "", uploadFormCount: 0, uploadRouteCount: 0 },
  }),
  finding({
    id: "security-password-field-security",
    checkKey: "password-field-security",
    title: "Password field security",
    status: "info",
    severity: "info",
    evidence: { checkedUrl: "", passwordFormCount: 0 },
  }),
]);

assert.equal(googleLike.counts.confirmedExploitableVulnerabilities, 0);
assert.equal(googleLike.counts.likelyHighImpactIssues, 0);
assert.equal(googleLike.coverageConfidence.level, "High");
assert.ok(googleLike.security.score >= 82 && googleLike.security.score <= 90, `Google-like score was ${googleLike.security.score}`);
assert.ok(["Low Risk", "Medium Risk"].includes(googleLike.security.riskLabel), `Google-like risk was ${googleLike.security.riskLabel}`);
assert.equal(googleLike.recommendedFirstLabel, "Recommended first review");
assert.ok(googleLike.recommendedFirstFix?.title.startsWith("Review unconfirmed reflected input indicators"));
assert.ok(!googleLike.topFixes.some((entry) => entry.title === "XSS evidence review"));
assert.ok(!googleLike.topFixes.some((entry) => /upload and form/i.test(entry.title)));
assert.ok(!googleLike.topFixes.some((entry) => /robots/i.test(entry.title)));

const kidytLike = report([
  finding({
    id: "security-browser-rendered-crawl-coverage",
    checkKey: "browser-rendered-crawl-coverage",
    title: "Browser-rendered crawl coverage",
    status: "warning",
    severity: "low",
    confidence: "likely",
    evidence: { checkedUrl: "https://kidyt.example", summary: "Browser rendering was attempted but did not produce a rendered page snapshot." },
  }),
  finding({
    id: "security-authentication-surface-review",
    checkKey: "authentication-surface-review",
    title: "Authentication surface review",
    status: "warning",
    severity: "medium",
    confidence: "likely",
    evidence: { checkedUrl: "https://kidyt.example/login", authSurfaceDetected: true, authRouteCount: 1, passwordFormCount: 1 },
  }),
  finding({
    id: "security-password-field-security",
    checkKey: "password-field-security",
    title: "Password field security",
    status: "warning",
    severity: "medium",
    confidence: "likely",
    evidence: { checkedUrl: "https://kidyt.example/login", passwordFormCount: 1, passwordForms: [{ url: "https://kidyt.example/login" }] },
  }),
  finding({
    id: "security-file-upload-risk-indicators",
    checkKey: "file-upload-risk-indicators",
    title: "File upload risk indicators",
    status: "warning",
    severity: "medium",
    confidence: "likely",
    evidence: { checkedUrl: "https://kidyt.example/upload", uploadFormCount: 1, uploadRouteCount: 1, uploadForms: [{ url: "https://kidyt.example/upload" }] },
  }),
  finding({
    id: "security-reflected-input-exposure",
    checkKey: "reflected-input-exposure",
    title: "Reflected input exposure",
    status: "warning",
    severity: "medium",
    confidence: "likely",
    evidence: { checkedUrl: "https://kidyt.example/?s=test", reflectedParameters: [{ url: "https://kidyt.example/?s=x", parameter: "s", context: "html" }] },
  }),
  finding({
    id: "security-xss-risk-indicators",
    checkKey: "xss-risk-indicators",
    title: "XSS evidence review",
    status: "warning",
    severity: "medium",
    confidence: "likely",
    evidence: { checkedUrl: "https://kidyt.example", reflections: [{ url: "https://kidyt.example/?s=x", parameter: "s", context: "html" }] },
  }),
  finding({
    id: "security-technology-fingerprinting",
    checkKey: "technology-fingerprinting",
    title: "Technology fingerprinting",
    status: "warning",
    severity: "low",
    confidence: "likely",
    evidence: { checkedUrl: "https://kidyt.example", technologies: ["WordPress 6.2", "wp-content"] },
  }),
]);

assert.ok(kidytLike.security.score >= 55 && kidytLike.security.score <= 68, `Kidyt-like score was ${kidytLike.security.score}`);
assert.ok(["Medium Risk", "High Risk"].includes(kidytLike.security.riskLabel), `Kidyt-like risk was ${kidytLike.security.riskLabel}`);
assert.ok(kidytLike.topFixes.some((entry) => /auth.*form|upload and form|authentication and form/i.test(entry.title)));

const juiceFindings = [
  finding({
    id: "security-sql-injection-risk-indicators",
    checkKey: "sql-injection-risk-indicators",
    title: "SQL injection risk indicators",
    status: "fail",
    severity: "critical",
    confidence: "confirmed",
    evidenceStrength: "exploit-proof",
    isFixableVulnerability: true,
    affectedUrl: "https://juice.example/rest/products/search?q=1",
    affectedParameter: "q",
    capabilitiesGained: ["database_query_manipulation"],
    evidence: {
      checkedUrl: "https://juice.example/rest/products/search?q=1",
      parameter: "q",
      recordExpansion: true,
      evidenceStrength: "exploit-proof",
    },
  }),
  finding({
    id: "security-authentication-bypass-probe",
    checkKey: "authentication-bypass-probe",
    title: "Authentication bypass",
    status: "fail",
    severity: "critical",
    confidence: "confirmed",
    evidenceStrength: "exploit-proof",
    isFixableVulnerability: true,
    affectedUrl: "https://juice.example/rest/user/login",
    capabilitiesGained: ["authenticated_context"],
    evidence: {
      checkedUrl: "https://juice.example/rest/user/login",
      authenticatedVerification: true,
      evidenceStrength: "exploit-proof",
    },
  }),
];
const juiceShop = report(juiceFindings);

assert.ok(juiceShop.primaryAttackPath, "Juice Shop profile should build an attack path");
assert.equal(juiceShop.recommendedFirstLabel, "Recommended first fix");
assert.equal(juiceShop.security.riskLabel, "Critical Risk");
assert.ok(juiceShop.security.score <= 30, `Juice Shop score was ${juiceShop.security.score}`);
assert.ok(/SQL injection|Authentication bypass/i.test(juiceShop.recommendedFirstFix?.title ?? ""));

console.log("Report prioritization regression checks passed");
