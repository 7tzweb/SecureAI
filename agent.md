# AGENT.md

## Purpose

This file is the short, current source of truth for the project.

Use it for orientation only. Do not treat it as a full product spec, and do not duplicate long requirements here.
Historical detail belongs in the archive under `docs/archive/`.

## Product

CyberAudit is a Next.js web app that scans a public website and shows a live audit across:

- Security
- SEO
- Performance

## Current User Flow

1. User enters a public domain and starts a scan.
2. The scan is created immediately and processed asynchronously.
3. Results stream into the report page while work is still running.
4. Anonymous users can view the report summary and findings.
5. Exact remediation details and fix guidance require Google sign-in.
6. When a user signs in from a report, the scan is claimed into that account when allowed.
7. Signed-in users get 3 free scans.
8. Additional scans are sold as a PayPal credit pack: 30 scans for $4.90.

## Core Stack

- Next.js App Router
- TypeScript
- Tailwind CSS
- Firebase Authentication
- Firebase Admin / Firestore when configured
- Redis + BullMQ when configured
- Local file-backed fallback repository when Firebase is unavailable

## Important Rules

1. Prefer small, non-breaking changes that preserve the existing UX and flow.
2. Keep scans asynchronous; do not move long-running work into request/response handlers.
3. Prefer passive, low-risk checks. Do not add destructive or aggressive scanning behavior.
4. Keep Google sign-in gating only around saved history, account linkage, and fix guidance.
5. Keep billing aligned with the current PayPal credit model unless explicitly asked to change it.
6. Split new work into focused modules instead of growing already-large files.
7. Keep docs short and current. Long archives should stay outside the active working context.

## Active Routes

- `/`
- `/scans/[scanId]`
- `/history`

## Important APIs

- `POST /api/scans`
- `GET /api/scans/[scanId]`
- `GET /api/scans/[scanId]/findings`
- `GET /api/scans/[scanId]/events`
- `POST /api/scans/[scanId]/claim`
- `GET /api/me/usage`
- `GET|POST|DELETE /api/auth/session`
- `POST /api/billing/paypal/order`
- `POST /api/billing/paypal/capture`

## Docs Policy

- Keep `HISTORY.md` compact.
- Put old or verbose history in `docs/archive/history/`.
- If a document becomes long enough that it must be reread often, shorten it.
