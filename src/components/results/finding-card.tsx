"use client";

import { useState } from "react";
import {
  AlertOctagon,
  Check,
  ChevronDown,
  ChevronUp,
  CircleAlert,
  Info,
  Lock,
  MapPin,
  ShieldAlert,
  Wrench,
} from "lucide-react";
import {
  type FindingEvidenceLocation,
  type ScanFinding,
  type ScanFindingEvidence,
} from "@/lib/types";
import { deriveFindingStatus, getConfidenceStyles, getSeverityStyles, getStatusStyles } from "@/lib/utils";

function StatusIcon({ finding }: { finding: ScanFinding }) {
  const status = deriveFindingStatus(finding);
  switch (status) {
    case "pass":
      return <Check className="h-7 w-7" />;
    case "fail":
      return finding.severity === "critical" ? (
        <AlertOctagon className="h-7 w-7" />
      ) : (
        <CircleAlert className="h-7 w-7" />
      );
    case "warning":
      return <CircleAlert className="h-7 w-7" />;
    case "info":
    default:
      return <Info className="h-7 w-7" />;
  }
}

function statusSurface(status: ReturnType<typeof deriveFindingStatus>) {
  switch (status) {
    case "pass":
      return "bg-emerald-50 text-emerald-600";
    case "warning":
      return "bg-amber-50 text-amber-500";
    case "fail":
      return "bg-red-50 text-red-500";
    case "info":
    default:
      return "bg-slate-100 text-slate-500";
  }
}

function humanizeKey(key: string) {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/^\w/, (value) => value.toUpperCase());
}

function formatEvidenceValue(value: unknown) {
  const compact = (input: string) =>
    input.length > 700 ? `${input.slice(0, 697).trimEnd()}...` : input;
  if (typeof value === "string") {
    return compact(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value) && value.every((entry) => typeof entry === "string")) {
    return compact(value.join(", "));
  }
  if (Array.isArray(value)) {
    return compact(
      value
        .slice(0, 4)
        .map((entry) =>
          typeof entry === "object" && entry !== null
            ? JSON.stringify(entry)
            : String(entry),
        )
        .join(" | "),
    );
  }
  if (typeof value === "object" && value !== null) {
    return compact(JSON.stringify(value));
  }
  return null;
}

function isLocation(value: unknown): value is FindingEvidenceLocation {
  return Boolean(
    value &&
      typeof value === "object" &&
      "label" in value &&
      typeof value.label === "string",
  );
}

function extractLocations(evidence: ScanFindingEvidence) {
  return Array.isArray(evidence.locations) ? evidence.locations.filter(isLocation) : [];
}

function extractEvidenceMeta(evidence: ScanFindingEvidence) {
  return Object.entries(evidence)
    .filter(([key]) => !["checkedUrl", "expectedLocation", "summary", "locations"].includes(key))
    .map(([key, value]) => ({
      label: humanizeKey(key),
      value: formatEvidenceValue(value),
    }))
    .filter((entry): entry is { label: string; value: string } => Boolean(entry.value));
}

function LocationCard({ location }: { location: FindingEvidenceLocation }) {
  return (
    <div className="rounded-[1.2rem] border border-white/70 bg-white/70 p-4 shadow-[0_8px_24px_rgba(148,163,184,0.12)]">
      <p className="text-sm font-semibold text-slate-900">{location.label}</p>
      <div className="mt-3 space-y-2 text-xs leading-6 text-slate-500">
        {location.path ? (
          <p>
            <span className="font-semibold uppercase text-[var(--ink-soft)]">Path</span>{" "}
            {location.path}
          </p>
        ) : null}
        {location.selector ? (
          <p>
            <span className="font-semibold uppercase text-[var(--ink-soft)]">Selector</span>{" "}
            {location.selector}
          </p>
        ) : null}
        {location.url ? (
          <p className="break-all">
            <span className="font-semibold uppercase text-[var(--ink-soft)]">URL</span>{" "}
            {location.url}
          </p>
        ) : null}
        {location.attribute ? (
          <p>
            <span className="font-semibold uppercase text-[var(--ink-soft)]">Attribute</span>{" "}
            {location.attribute}
          </p>
        ) : null}
        {location.value ? (
          <p className="break-all">
            <span className="font-semibold uppercase text-[var(--ink-soft)]">Value</span>{" "}
            {location.value}
          </p>
        ) : null}
        {location.context ? (
          <p>
            <span className="font-semibold uppercase text-[var(--ink-soft)]">Context</span>{" "}
            {location.context}
          </p>
        ) : null}
        {location.note ? (
          <p>
            <span className="font-semibold uppercase text-[var(--ink-soft)]">Note</span>{" "}
            {location.note}
          </p>
        ) : null}
      </div>
    </div>
  );
}

export function FindingCard({
  finding,
  onUnlock,
  unlockDisabled = false,
}: {
  finding: ScanFinding;
  onUnlock?: () => void;
  unlockDisabled?: boolean;
}) {
  const [showDetails, setShowDetails] = useState(true);
  const status = deriveFindingStatus(finding);
  const evidence = finding.evidence ?? {};
  const confidence = finding.confidence ?? "info";
  const locations = extractLocations(evidence);
  const evidenceMeta = extractEvidenceMeta(evidence);
  const checkedUrl = typeof evidence.checkedUrl === "string" ? evidence.checkedUrl : null;
  const expectedLocation =
    typeof evidence.expectedLocation === "string" ? evidence.expectedLocation : null;
  const summary = typeof evidence.summary === "string" ? evidence.summary : null;
  const hasEvidence = Boolean(checkedUrl || expectedLocation || summary || evidenceMeta.length || locations.length);

  return (
    <article className="glass-panel flex flex-col items-stretch gap-4 overflow-hidden rounded-[1.5rem] bg-white/60 p-5 transition-all hover:shadow-[0_12px_40px_rgba(0,0,0,0.05)] sm:flex-row sm:items-start sm:gap-6 sm:rounded-[2rem] sm:p-6">
      <div
        className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-[1.25rem] shadow-sm ${statusSurface(status)}`}
      >
        <StatusIcon finding={finding} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="mb-2 flex flex-wrap items-center gap-3">
          <h3 className="min-w-0 break-words text-lg font-semibold text-slate-900">{finding.title}</h3>
          <span
            className={`rounded-full px-3 py-1 text-[10px] font-bold uppercase ${getStatusStyles(status)}`}
          >
            {status}
          </span>
          {(status === "warning" || status === "fail") ? (
            <span
              className={`rounded-full px-3 py-1 text-[10px] font-bold uppercase ${getSeverityStyles(finding.severity)}`}
            >
              {finding.severity}
            </span>
          ) : null}
          <span className="rounded-full bg-slate-100 px-3 py-1 text-[10px] font-bold uppercase text-slate-600">
            {finding.category}
          </span>
          <span
            className={`rounded-full px-3 py-1 text-[10px] font-bold uppercase ${getConfidenceStyles(confidence)}`}
          >
            {confidence}
          </span>
        </div>
        <p className="max-w-3xl text-sm leading-7 text-slate-500">{finding.shortDescription}</p>
        <div className="mt-3 flex flex-wrap gap-2">
          {typeof finding.riskScore === "number" ? (
            <span className="rounded-full border border-slate-200 bg-white/75 px-3 py-1 text-[10px] font-bold uppercase text-slate-700">
              Risk {finding.riskScore}/100
            </span>
          ) : null}
          {finding.priorityLabel ? (
            <span className="rounded-full border border-blue-100 bg-blue-50 px-3 py-1 text-[10px] font-bold uppercase text-blue-700">
              {finding.priorityLabel}
            </span>
          ) : null}
          {finding.attackPathParticipant ? (
            <span className="rounded-full border border-purple-100 bg-purple-50 px-3 py-1 text-[10px] font-bold uppercase text-purple-700">
              Attack path
            </span>
          ) : null}
          {finding.publicEndpoint ? (
            <span className="rounded-full border border-slate-200 bg-white/75 px-3 py-1 text-[10px] font-bold uppercase text-slate-700">
              Public endpoint
            </span>
          ) : null}
        </div>

        {finding.locked ? (
          <div className="mt-4 rounded-[1.4rem] border border-dashed border-slate-300 bg-slate-50 p-4 text-sm text-slate-500">
            <div className="flex items-center gap-2 font-semibold text-slate-900">
              <ShieldAlert className="h-4 w-4 text-[var(--warning)]" />
              Sign in with Google to view fix details
            </div>
            <p className="mt-2">
              The check result stays visible, but the remediation steps, exact locations, and evidence payloads stay locked until a verified Google session is connected.
            </p>
          </div>
        ) : showDetails ? (
          <div className="mt-4 space-y-3">
            <div className="grid gap-3 lg:grid-cols-2">
              <div className="rounded-[1.4rem] bg-[var(--surface-muted)] p-4">
                <p className="text-[11px] font-bold uppercase text-[var(--ink-soft)]">
                  Why it matters
                </p>
                <p className="mt-2 text-sm leading-7 text-[var(--ink-muted)]">
                  {finding.whyItMatters}
                </p>
              </div>
              <div className="rounded-[1.4rem] bg-[var(--surface-muted)] p-4">
                <p className="text-[11px] font-bold uppercase text-[var(--ink-soft)]">
                  Recommendation
                </p>
                <p className="mt-2 text-sm leading-7 text-[var(--ink-muted)]">
                  {finding.recommendation}
                </p>
              </div>
            </div>

            {hasEvidence ? (
              <div className="rounded-[1.4rem] bg-[var(--surface-muted)] p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <MapPin className="h-4 w-4 text-[var(--primary)]" />
                  <p className="text-[11px] font-bold uppercase text-[var(--ink-soft)]">
                    Exact location
                  </p>
                </div>

                {summary ? (
                  <p className="mt-3 text-sm leading-7 text-[var(--ink-muted)]">{summary}</p>
                ) : null}

                {(checkedUrl || expectedLocation) ? (
                  <div className="mt-3 grid gap-3 lg:grid-cols-2">
                    {checkedUrl ? (
                      <div className="rounded-[1.1rem] border border-white/70 bg-white/70 p-3">
                        <p className="text-[10px] font-bold uppercase text-[var(--ink-soft)]">
                          Checked URL
                        </p>
                        <p className="mt-2 break-all text-sm leading-6 text-slate-700">{checkedUrl}</p>
                      </div>
                    ) : null}
                    {expectedLocation ? (
                      <div className="rounded-[1.1rem] border border-white/70 bg-white/70 p-3">
                        <p className="text-[10px] font-bold uppercase text-[var(--ink-soft)]">
                          Expected location
                        </p>
                        <p className="mt-2 break-all text-sm leading-6 text-slate-700">
                          {expectedLocation}
                        </p>
                      </div>
                    ) : null}
                  </div>
                ) : null}

                {evidenceMeta.length > 0 ? (
                  <div className="mt-3 flex flex-wrap gap-2">
                    {evidenceMeta.map((entry) => (
                      <div
                        key={`${finding.id}-${entry.label}`}
                        className="rounded-full border border-white/70 bg-white/70 px-3 py-1.5 text-xs text-slate-600"
                      >
                        <span className="font-semibold text-slate-900">{entry.label}:</span> {entry.value}
                      </div>
                    ))}
                  </div>
                ) : null}

                {locations.length > 0 ? (
                  <div className="mt-4 grid gap-3 xl:grid-cols-2">
                    {locations.map((location, index) => (
                      <LocationCard
                        key={`${finding.id}-${location.label}-${location.path ?? index}`}
                        location={location}
                      />
                    ))}
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        ) : null}
      </div>
      <div className="shrink-0 sm:pt-0">
        {finding.locked ? (
          <button
            type="button"
            disabled={unlockDisabled}
            onClick={onUnlock}
            className="inline-flex w-full items-center justify-center gap-2 rounded-full bg-white/50 px-5 py-2.5 text-sm font-semibold text-[var(--primary)] shadow-sm transition-all hover:bg-[var(--primary)] hover:text-white disabled:cursor-not-allowed disabled:opacity-60 sm:w-auto"
          >
            <Lock className="h-4 w-4" />
            Sign in
          </button>
        ) : (
          <button
            type="button"
            onClick={() => setShowDetails((current) => !current)}
            className="inline-flex w-full items-center justify-center gap-2 rounded-full bg-white/50 px-5 py-2.5 text-sm font-semibold text-[var(--primary)] shadow-sm transition-all hover:bg-white sm:w-auto"
          >
            <Wrench className="h-4 w-4" />
            {showDetails ? (status === "pass" ? "Hide Details" : "Hide Fix") : status === "pass" ? "View Details" : "View Fix"}
            {showDetails ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </button>
        )}
      </div>
    </article>
  );
}
