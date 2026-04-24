# HISTORY.md

## 2026-04-22 00:00 - Initial Project Instructions Added

### Summary
- Created the repository change history file
- Established the required format for all future entries
- This entry is a placeholder baseline and should remain in the file

### Files Changed
- AGENT.md
- HISTORY.md

### Data / Schema
- None

### Env Changes
- None

### Routes / APIs
- None

### Notes
- Future coding runs must append new entries instead of rewriting prior history
- Every meaningful change must be logged here

### Breaking Changes
- None

## 2026-04-22 17:05 - Switched Fix Access To Google Sessions And Wired Local Auth Env

### Summary
- Changed report access so all checks remain visible to everyone while remediation details, exact locations, and evidence now unlock through Google sign-in instead of the old premium checkout flow
- Reworked the results workspace CTA so it syncs or creates a Google-backed server session, optionally claims anonymous scans into the signed-in account, and removes checkout from the main fix-access path
- Added local Firebase and Google OAuth environment wiring from the provided credentials and made Firebase Admin detection tolerate a missing `serviceAccountKey.json` file by falling back to token verification

### Files Changed
- .env.example
- .env.local
- .gitignore
- HISTORY.md
- README.md
- src/app/page.tsx
- src/components/history/history-client.tsx
- src/components/providers/auth-provider.tsx
- src/components/results/finding-card.tsx
- src/components/results/results-client.tsx
- src/lib/types.ts
- src/server/config.ts
- src/server/scans/service.ts

### Data / Schema
- Renamed report access flags in API response types from `viewerCanAccessPremium` to `viewerCanAccessFixes`

### Env Changes
- Added a local `.env.local` with the provided Firebase client config, Google OAuth config, OpenAI key, and placeholder Stripe keys
- Added `FIREBASE_SERVICE_ACCOUNT_PATH`, Google OAuth, Vite-prefixed Firebase vars, and `OPENAI_API_KEY` to `.env.example`
- Added `serviceAccountKey.json` to `.gitignore`

### Routes / APIs
- Changed `GET /api/scans/[scanId]` and `GET /api/scans/[scanId]/findings` responses to use `viewerCanAccessFixes`
- Changed fix access behavior so a valid Google session unlocks result details without running the checkout route

### Notes
- If `serviceAccountKey.json` is still missing, Google login can still create a secure server session through Firebase token verification, but Firestore/Admin-only features stay disabled
- Anonymous scans are claimed into the signed-in account when possible so they continue showing up in history after Google login

### Breaking Changes
- `ScanSummaryResponse.viewerCanAccessPremium` was renamed to `viewerCanAccessFixes`
- `ScanFindingsResponse.viewerCanAccessPremium` was renamed to `viewerCanAccessFixes`

## 2026-04-22 22:50 - Unified Top Navigation And Added Account Scan Quotas

### Summary
- Replaced the page-specific top bars with one shared header across the dashboard, scan workspace, and history view so navigation, recent activity, account access, and sign-out stay consistent between screens
- Added a new-audit launcher directly inside the scan results page so another scan can be started immediately without leaving the current report
- Enforced a free quota of 5 scans per signed-in Google account and added a $9 Stripe upgrade path that unlocks unlimited scans for that account
- Added recent-activity and account panels in the shared header, including live scan quota status and upgrade entry points
- Added Stripe checkout confirmation support on return from checkout so the plan can activate even when only the secret key is configured and webhooks are not yet wired

### Files Changed
- .env.example
- HISTORY.md
- README.md
- src/app/layout.tsx
- src/app/page.tsx
- src/app/api/billing/checkout/route.ts
- src/app/api/billing/confirm/route.ts
- src/app/api/billing/webhook/route.ts
- src/app/api/me/usage/route.ts
- src/components/history/history-client.tsx
- src/components/landing/start-audit-form.tsx
- src/components/layout/site-header.tsx
- src/components/results/results-client.tsx
- src/lib/types.ts
- src/server/api/errors.ts
- src/server/billing/service.ts
- src/server/billing/stripe.ts
- src/server/config.ts
- src/server/repository/file-store.ts
- src/server/repository/firestore-store.ts
- src/server/repository/memory-store.ts
- src/server/repository/types.ts
- src/server/scans/schemas.ts
- src/server/scans/service.ts

### Data / Schema
- Added `ScanQuotaSummary` for account-level scan usage and upgrade state
- Added repository support for counting scans per signed-in user

### Env Changes
- Added `STRIPE_SCAN_PLAN_PRICE_USD` so the unlimited plan can fall back to inline `$9` Stripe pricing when no price id is provided

### Routes / APIs
- Added `GET /api/me/usage`
- Added `POST /api/billing/confirm`
- Changed `POST /api/billing/checkout` so it now supports account-level unlimited-scan upgrades in addition to report-specific billing metadata
- Changed `POST /api/scans` so new scan creation now requires a signed-in Google session and respects the 5-scan quota

### Notes
- The shared header is now the single navigation surface for dashboard, audits, threats, history, notifications, and account actions
- Stripe checkout itself still needs a valid `STRIPE_SECRET_KEY` to run; the code now works with inline `$9` pricing even if `STRIPE_PRICE_ID_PREMIUM` is empty
- Verified with `npm run lint`, `npm run typecheck`, and `npm run build`

### Breaking Changes
- New scan creation now requires a signed-in Google session

## 2026-04-22 16:20 - Replaced Heuristic Findings With Real URL-Based Checks

### Summary
- Reworked the scan engine so Security, SEO, and Performance now emit real checks against the user-provided URL instead of a short generic findings list
- Added shared audit artifacts with cached page fetches, limited internal crawl, asset probing, TLS inspection, and sampled link/resource analysis so category workers stay asynchronous but avoid repeating the same network work
- Expanded Security to cover HTTPS, redirect behavior, certificate validation and expiry, header policies, cookie flags, insecure resources, exposed files, directory listing, technology hints, and CDN/WAF hints
- Expanded SEO to cover title, description, canonical, robots, sitemap, robots meta, heading structure, alt coverage, social metadata, structured data, viewport, lang, broken links, and duplicate metadata across a limited crawl
- Expanded Performance to cover TTFB, HTML transfer time, request count, page weight, JS/CSS weight, heavy images, modern image formats, sampled image size mismatch, lazy loading, compression, cache headers, blocking assets, third-party weight, redirect chains, fonts, DOM size, and heuristic main-thread/LCP/CLS hints
- Added explicit `pass`, `warning`, `fail`, and `info` statuses to result cards and changed scoring so passing checks no longer lower the category score

### Files Changed
- HISTORY.md
- src/lib/types.ts
- src/lib/utils.ts
- src/components/results/finding-card.tsx
- src/components/results/results-client.tsx
- src/server/scans/artifacts.ts
- src/server/scans/helpers.ts
- src/server/scans/performance.ts
- src/server/scans/security.ts
- src/server/scans/seo.ts
- src/server/scans/types.ts

### Data / Schema
- Added `findingStatuses` and `ScanFinding.status` so each check can be represented as `pass`, `warning`, `fail`, or `info`
- Added redirect-chain and total-response timing fields to `HttpAttempt`
- Added shared audit artifact structures for crawled pages, link probes, asset probes, and TLS inspection data

### Env Changes
- None

### Routes / APIs
- Changed `GET /api/scans/[scanId]/findings` so each category now returns full check inventories with real status/evidence data instead of only issue-style findings

### Notes
- The new scanners use real network fetches, limited crawl depth, and sampled asset probes to stay practical and inexpensive while still being tied to the requested URL
- Browser-only style metrics such as main-thread pressure, LCP-style, and CLS-style remain explicit heuristics based on sampled HTML/assets rather than pretending to be Lighthouse metrics
- Verified with `npm run lint`, `npm run typecheck`, `npm run build`, live `POST /api/scans`, and live `GET /api/scans/[scanId]/findings`
- Refreshed the existing `6e7c0d0b-ed20-462a-a442-2c8d7ee1fedb` local report so it now uses the real URL-based check engine output

### Breaking Changes
- `ScanFinding` records now include a `status` field and richer evidence payloads

## 2026-04-22 15:55 - Added Exact Finding Locations And Open Fix Panels

### Summary
- Added structured finding evidence so scans can return exact checked URLs, expected locations, and sampled element locations instead of only generic counters
- Enriched SEO, Security, and Performance scanners with concrete selectors, DOM paths, response-header locations, and resource URLs for actionable findings
- Reworked result cards so the fix/details area is open by default and now renders exact location data directly inside each finding card
- Refreshed the existing local `kidyt.com` scan data so the previously shared scan link now exposes the new evidence payloads

### Files Changed
- HISTORY.md
- src/lib/types.ts
- src/components/results/finding-card.tsx
- src/server/scans/helpers.ts
- src/server/scans/performance.ts
- src/server/scans/security.ts
- src/server/scans/seo.ts

### Data / Schema
- Added `ScanFindingEvidence` and `FindingEvidenceLocation` structures for `checkedUrl`, `expectedLocation`, `summary`, and `locations`
- Scan findings can now include sampled DOM element paths, CSS-like selectors, resolved asset URLs, response header locations, and note/context fields

### Env Changes
- None

### Routes / APIs
- Changed `GET /api/scans/[scanId]/findings` responses so evidence payloads include exact location metadata when the scanner can determine it

### Notes
- `View Fix` content is now expanded by default for unlocked findings and can be collapsed from the card action button
- Verified with `npm run lint`, `npm run typecheck`, `npm run build`, and live API checks against both a new `kidyt.com` scan and the previously shared scan link

### Breaking Changes
- None

## 2026-04-22 12:20 - Reworked Scan UX And Durable Local Runtime

### Summary
- Replaced the accidental prior UI with the new design direction from `page4.html` for the landing page and `page3.html` for the scan workspace
- Rebuilt the scan results page so it opens directly into live findings, adds a real top progress loader, and removes the old explanatory block above the findings list
- Added a file-backed local repository fallback so scans, findings, events, users, and payments persist across local dev restarts even without Firebase
- Fixed async category state races by switching queue updates to atomic scan mutations and added self-healing requeue logic for stale incomplete scans
- Added a recent scans API for the workspace sidebar and refreshed the history page to match the new workspace visual language

### Files Changed
- .gitignore
- HISTORY.md
- src/app/globals.css
- src/app/layout.tsx
- src/app/page.tsx
- src/app/history/page.tsx
- src/app/scans/[scanId]/page.tsx
- src/app/api/scans/recent/route.ts
- src/components/history/history-client.tsx
- src/components/landing/start-audit-form.tsx
- src/components/results/finding-card.tsx
- src/components/results/results-client.tsx
- src/server/queue/processor.ts
- src/server/repository/file-store.ts
- src/server/repository/firestore-store.ts
- src/server/repository/index.ts
- src/server/repository/memory-store.ts
- src/server/repository/types.ts
- src/server/scans/service.ts

### Data / Schema
- Added local runtime persistence file at `.cyberaudit/runtime-store.json` for fallback storage
- Added repository capability for atomic `mutateScan` updates to prevent category status overwrites during concurrent jobs
- Added repository capability for listing recent scans to power the workspace sidebar

### Env Changes
- None

### Routes / APIs
- Added `GET /api/scans/recent`
- Changed scan summary behavior so stale incomplete scans are automatically resumed on access

### Notes
- Existing stale scans are auto-requeued the next time they are opened, which repairs previously partial reports created before the queue race fix
- The landing page and scan workspace now follow `page4.html` and `page3.html`; the previous rendered design is no longer used
- Verified with `npm run lint`, `npm run typecheck`, `npm run build`, and live API checks against local scan routes

### Breaking Changes
- None

## 2026-04-22 12:35 - Scaffolded CyberAudit Product

### Summary
- Built a full Next.js 16 App Router application for CyberAudit with a landing page, live results page, and authenticated history page
- Added async scan orchestration with category workers for security, SEO, and performance plus local in-memory fallback and Redis/BullMQ support
- Implemented Firebase session hooks, Google sign-in client plumbing, Firestore repository support, and Stripe checkout/webhook flows with safe config fallbacks
- Added static reference designs to `page1.html` and `page2.html` because the original design source files were empty

### Files Changed
- package.json
- next.config.ts
- tsconfig.json
- .env.example
- README.md
- page1.html
- page2.html
- src/app/layout.tsx
- src/app/globals.css
- src/app/page.tsx
- src/app/history/page.tsx
- src/app/scans/[scanId]/page.tsx
- src/app/api/auth/session/route.ts
- src/app/api/scans/route.ts
- src/app/api/scans/[scanId]/route.ts
- src/app/api/scans/[scanId]/findings/route.ts
- src/app/api/scans/[scanId]/events/route.ts
- src/app/api/scans/[scanId]/claim/route.ts
- src/app/api/me/scans/route.ts
- src/app/api/billing/checkout/route.ts
- src/app/api/billing/webhook/route.ts
- src/components/brand/logo.tsx
- src/components/history/history-client.tsx
- src/components/landing/start-audit-form.tsx
- src/components/layout/site-header.tsx
- src/components/providers/auth-provider.tsx
- src/components/results/finding-card.tsx
- src/components/results/results-client.tsx
- src/components/ui/badge.tsx
- src/components/ui/button.tsx
- src/components/ui/card.tsx
- src/components/ui/input.tsx
- src/components/ui/progress-bar.tsx
- src/components/ui/skeleton.tsx
- src/lib/firebase-client.ts
- src/lib/public-config.ts
- src/lib/types.ts
- src/lib/utils.ts
- src/server/api/errors.ts
- src/server/auth/session.ts
- src/server/billing/stripe.ts
- src/server/config.ts
- src/server/firebase-admin.ts
- src/server/queue/index.ts
- src/server/queue/bullmq-driver.ts
- src/server/queue/local-driver.ts
- src/server/queue/processor.ts
- src/server/queue/types.ts
- src/server/rate-limit.ts
- src/server/repository/index.ts
- src/server/repository/firestore-store.ts
- src/server/repository/memory-store.ts
- src/server/repository/types.ts
- src/server/scans/helpers.ts
- src/server/scans/performance.ts
- src/server/scans/schemas.ts
- src/server/scans/security.ts
- src/server/scans/seo.ts
- src/server/scans/service.ts
- src/server/scans/types.ts
- src/server/worker/index.ts

### Data / Schema
- Added repository support for `users`, `scans`, `scans/{scanId}/findings`, `scans/{scanId}/events`, and `payments`
- Added scan category status tracking, premium unlock state, per-user history linkage, and payment metadata persistence
- Firestore is the production repository target; an in-memory repository is used automatically when Firebase Admin env vars are absent

### Env Changes
- NEXT_PUBLIC_APP_URL: base URL for redirects and Stripe success/cancel flows
- NEXT_PUBLIC_FIREBASE_API_KEY: Firebase client auth setup
- NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN: Firebase client auth setup
- NEXT_PUBLIC_FIREBASE_PROJECT_ID: Firebase client setup
- NEXT_PUBLIC_FIREBASE_APP_ID: Firebase client setup
- NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID: Firebase client setup
- FIREBASE_PROJECT_ID: Firebase Admin / Firestore setup
- FIREBASE_CLIENT_EMAIL: Firebase Admin credentials
- FIREBASE_PRIVATE_KEY: Firebase Admin credentials
- REDIS_URL: enables BullMQ queueing and external worker mode
- STRIPE_SECRET_KEY: server-side Stripe integration
- STRIPE_WEBHOOK_SECRET: Stripe webhook verification
- NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY: reserved for client-side Stripe usage
- STRIPE_PRICE_ID_PREMIUM: Stripe price used for premium unlock checkout

### Routes / APIs
- Added `POST /api/scans`
- Added `GET /api/scans/[scanId]`
- Added `GET /api/scans/[scanId]/findings`
- Added `GET /api/scans/[scanId]/events`
- Added `POST /api/scans/[scanId]/claim`
- Added `GET /api/me/scans`
- Added `GET|POST|DELETE /api/auth/session`
- Added `POST /api/billing/checkout`
- Added `POST /api/billing/webhook`

### Notes
- The original `page1.html` and `page2.html` were empty, so matching reference HTML files were created from the implemented design language
- When `REDIS_URL` is unset, scans are processed by an in-process async queue; when it is set, run `npm run worker`
- Without Firebase client/admin env vars, Google login and persistent storage fall back safely instead of failing open
- Verified with `npm run lint`, `npm run typecheck`, and `npm run build`

### Breaking Changes
- None
