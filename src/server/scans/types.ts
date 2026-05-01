import { type ScanFinding } from "@/lib/types";

export interface NormalizedTarget {
  originalInput: string;
  normalizedTarget: string;
  targetHostname: string;
  httpsUrl: string;
  httpUrl: string;
  authCookieHeader?: string | null;
  secondaryAuthCookieHeader?: string | null;
}

export interface HttpAttempt {
  requestUrl: string;
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  bodyText: string;
  durationMs: number;
  totalDurationMs: number;
  redirectChain: Array<{
    url: string;
    status: number;
    location: string;
  }>;
}

export interface PageContext {
  https: HttpAttempt | null;
  http: HttpAttempt | null;
  primary: HttpAttempt | null;
}

export interface CategoryScanResult {
  findings: ScanFinding[];
  score: number;
}
