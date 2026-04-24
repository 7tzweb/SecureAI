# AGENT.md

## Role

You are the implementation agent for a production-ready web application called **CyberAudit**.

Your job is to build, maintain, and extend a **full working product** in **Node.js** with a modern frontend, an asynchronous scan pipeline, Firebase-based data/auth, Google login, and payment gating for premium details.

Do not treat this as an MVP. Build it as a solid, real product with clean architecture, modular code, good DX, and production-grade defaults.

---

## Global Rules

These rules apply on every single run, without needing to be repeated by the user.

1. Always use **best practices** for architecture, security, code quality, error handling, validation, and maintainability.
2. Prefer **TypeScript** across the project.
3. Keep the project in the **Node.js ecosystem**.
4. Use **clean modular architecture**. Avoid god files and avoid mixing UI, orchestration, and scanner logic.
5. Every change must be recorded in `HISTORY.md` using the required format in this document.
6. Reuse the visual design from `page1.html` and `page2.html` as the design source of truth.
7. Do not redesign the product unless explicitly asked. Match the existing design language as closely as possible.
8. All scans must run **asynchronously** and **in parallel where safe**.
9. The API must return quickly; long-running work must be handled by background jobs.
10. Prefer passive and safe scanning. Do not implement destructive or aggressive security attacks.
11. Make implementation decisions that support a real SaaS product, not just a demo.
12. When something is ambiguous, choose the option that is safer, more maintainable, and more production-ready.
13. If you add a dependency, configure it correctly and document it in `HISTORY.md`.
14. If you change env vars, routes, data models, auth, billing, or job behavior, document it in `HISTORY.md`.
15. Preserve backward compatibility when reasonable.
16. Use strong validation for all public inputs.
17. Use rate limiting, auth checks, and abuse protections anywhere relevant.
18. Write code that is easy for another engineer to continue.

---

## Product Summary

The product lets a user enter a website domain, start a scan, and receive a modern audit report.

The user experience has two main visual pages:

- `page4.html` = landing/search page
- `page3.html` = results/report page

The application scans a website across **three categories**:

1. **Security**
2. **SEO**
3. **Performance**

The application must feel fast:
- create scan immediately
- show progress live
- execute checks asynchronously
- display partial results while more checks are still running

After a basic result is shown, the user can:
- sign in with Google
- request more details
- unlock extended details / premium report via payment

This is a product flow, not just a static analyzer.

---

## Required Tech Stack

Use the following stack unless there is a strong technical reason to slightly adjust it.

### Core
- **Next.js** (App Router)
- **Node.js**
- **TypeScript**
- **Tailwind CSS**
- **shadcn/ui** for UI primitives where useful

### Data / Auth
- **Firebase Authentication** for user auth
- **Google Sign-In** as the main auth method
- **Cloud Firestore** as the main application database
- **Firebase Admin SDK** on the server

### Background Jobs
- **Redis**
- **BullMQ**

### Scanning
- Native async HTTP requests from Node
- Optional browser-based checks via **Playwright** where needed

### Billing
- **Stripe** for payments

### Hosting
Use an architecture that can run on modern platforms. Keep the app deployable with environment variables and production settings.

---

## Important Architecture Note About Firebase

Firebase is the database/auth layer, but it is **not** the job queue.

Use:
- **Firestore** for users, scans, findings, usage, subscriptions metadata, history
- **Redis + BullMQ** for asynchronous background processing

Do not try to run the full scan pipeline directly inside request/response handlers.

---

## Main User Flows

## Flow 1: Anonymous user basic scan
1. User opens landing page based on `page1.html`.
2. User enters a domain.
3. User clicks Start Audit.
4. Backend creates a scan record and background jobs.
5. User is redirected to the results page based on `page2.html`.
6. The page shows live progress.
7. Basic findings and category scores appear incrementally.

## Flow 2: User signs in after seeing initial results
1. Anonymous user sees partial/basic report.
2. User clicks a CTA to continue with Google.
3. User signs in with Google via Firebase Auth.
4. The scan becomes linked to the user account.
5. History, saved scans, deeper details, and paid upgrade options become available.

## Flow 3: User requests more details
1. User clicks a CTA like “View Full Details” / “Unlock Complete Report”.
2. If not signed in: require Google login first.
3. If signed in but not paid: present billing/paywall flow.
4. After payment success, unlock premium sections and extended findings.

## Flow 4: Returning signed-in user
1. User signs in.
2. User sees scan history.
3. User can reopen previous scan results.
4. Paid users can access premium details across eligible scans based on billing rules.

---

## UI Requirements

## Page 1: Landing / Search Page
Design source: `page1.html`

### Purpose
Allow the user to input a domain and start a scan.

### Required elements
- product logo / brand
- simple top navigation matching the provided style
- large headline
- supporting subtitle
- single prominent domain input
- primary CTA button to start scan
- subtle trust/supporting indicators below input
- clean, light, premium design matching `page1.html`

### Behavior
- validate domain input
- normalize domain input
- prevent obviously invalid URLs
- disable button while creating a scan
- show loading feedback immediately
- create scan and navigate to results page

### Validation behavior
Accept:
- `example.com`
- `www.example.com`
- `https://example.com`

Normalize internally to a canonical target.

Reject:
- empty input
- malformed URLs
- unsupported protocols
- localhost/internal/private network targets unless explicitly supported by product rules

---

## Page 2: Results / Dashboard Page
Design source: `page2.html`

### Purpose
Show live scan progress and audit findings.

### Required sections
- scan target/domain
- overall progress
- category tabs: Security / SEO / Performance
- category score(s)
- overall score
- findings list cards
- severity badges
- right-side summary/sidebar matching design language
- CTA for full summary / more details
- auth upgrade/payment prompts where appropriate
- optional scan history access for logged-in users

### Behavior
- render immediately with skeleton/loading state
- subscribe to live updates
- update scores/findings incrementally
- preserve tab state in UI
- show clear statuses: queued / running / partial / completed / failed
- allow partial rendering when some workers finish before others

---

## Functional Requirements

## Scanning Categories

### 1. Security
This is the first and most important category.

#### Security checks to include

### A. Fast passive HTTP / header checks
These should run early and quickly.

- HTTPS present or not
- redirect from HTTP to HTTPS
- TLS certificate exists
- certificate expiration date
- certificate validity state
- HSTS header presence
- Content-Security-Policy header presence
- X-Frame-Options presence
- X-Content-Type-Options presence
- Referrer-Policy presence
- Permissions-Policy presence
- Cross-Origin-Opener-Policy presence
- Cross-Origin-Resource-Policy presence
- Cross-Origin-Embedder-Policy presence
- cache-control sanity for sensitive pages when detectable
- server header exposure
- x-powered-by exposure
- security.txt availability
- robots.txt availability

### B. Cookie security checks
- Secure flag
- HttpOnly flag
- SameSite presence
- weak or missing cookie attributes
- suspicious cookie exposure patterns

### C. Mixed content / transport checks
- insecure subresources on HTTPS page
- insecure form actions
- mixed passive/active content indicators
- downgrade risks when detectable

### D. Basic browser-executed checks
Use Playwright only when browser context is needed.

- presence of inline scripts patterns relevant to CSP guidance
- iframe embedding exposure indicators
- form password field served over insecure context
- client-side console security-related errors when useful
- third-party script inventory for awareness
- basic SRI presence for third-party scripts when detectable

### E. Common passive exposure checks
Safe, non-destructive, non-intrusive only.

- exposed `.git/HEAD` check
- exposed `.env` check
- exposed common backup file names
- exposed directory listing indicators
- default server pages / common misconfiguration indicators
- publicly reachable admin/login hints (informational only)
- suspicious headers or stack disclosure

### F. Domain / platform context checks
- DNS resolution success
- mail-related records presence if relevant
- basic CDN/WAF detection if useful for context
- technology fingerprinting for informational context only

### G. Security scoring model
Every finding must include:
- id
- title
- category = security
- severity = info / low / medium / high / critical
- short description
- why it matters
- remediation recommendation
- evidence payload
- optional references field
- premium-only boolean if the finding details are gated

Scoring:
- compute a security score from 0 to 100
- critical issues reduce score more than high, medium, low
- informational findings do not heavily penalize score
- score must be deterministic and explainable

### H. Security findings examples
Examples of report items:
- Missing Content Security Policy
- Missing HSTS
- Missing X-Content-Type-Options
- Missing HttpOnly on session cookie
- Mixed Content Detected
- Exposed `.git` endpoint
- TLS Certificate Expiring Soon
- Insecure Form Submission
- Missing SRI on third-party script

---

### 2. SEO
Implement a real but safe SEO audit.

Checks may include:
- title tag exists
- meta description exists
- canonical tag exists
- robots meta
- robots.txt presence
- sitemap.xml presence
- H1 presence
- heading structure quality
- image alt coverage (sample-based)
- open graph basics
- twitter card basics
- structured data presence
- indexability basics
- duplicate title/description hints where detectable on scanned page
- mobile viewport presence
- basic internal linking hints if crawl depth is limited

Each SEO finding should use the same finding schema.

---

### 3. Performance
Implement a practical performance audit.

Checks may include:
- TTFB estimate
- response time
- total page weight
- number of requests
- image optimization hints
- modern image format hints
- uncompressed asset hints
- cache header opportunities
- render-blocking asset hints
- large JS bundle hints
- large CSS bundle hints
- lazy-loading hints
- basic Core Web Vitals-oriented observations where feasible
- third-party script weight awareness

Each performance finding should use the same finding schema.

---

## Scan Execution Requirements

## Job orchestration
A scan must be split into async jobs.

### Recommended job structure
- `scan:create`
- `scan:security`
- `scan:seo`
- `scan:performance`
- optional child jobs inside each category

Example:
- `security:headers`
- `security:cookies`
- `security:tls`
- `security:exposures`
- `security:browser`
- `seo:metadata`
- `seo:indexability`
- `performance:network`
- `performance:assets`
- `performance:browser`

### Execution rules
- run independent checks in parallel
- enforce per-job timeout
- allow retries for transient failures
- keep scan status accurate
- store partial results continuously
- mark category complete independently of others

### Live updates
The UI must receive updates for:
- progress percentage
- current phase
- category status
- findings added
- score updates
- completion/failure state

Use a robust real-time strategy. Polling is acceptable initially, but a proper event-driven update approach is preferred.

---

## Data Model Requirements

Use Firestore collections/subcollections with clean naming.

Suggested collections:

### `users`
User profile and account metadata.

Suggested fields:
- uid
- email
- displayName
- photoURL
- createdAt
- lastLoginAt
- roles
- subscriptionStatus
- stripeCustomerId
- entitlementLevel

### `scans`
Top-level scan records.

Suggested fields:
- id
- target
- normalizedTarget
- targetHostname
- createdByUserId nullable
- createdAt
- updatedAt
- status
- progress
- overallScore
- securityScore
- seoScore
- performanceScore
- isAnonymous
- premiumUnlocked
- visibility
- latestPhase
- errorSummary nullable

### `scans/{scanId}/findings`
Detailed findings.

Suggested fields:
- id
- category
- severity
- title
- shortDescription
- whyItMatters
- recommendation
- evidence
- references
- premiumOnly
- createdAt
- updatedAt

### `scans/{scanId}/events`
Progress events / audit log for UI updates.

Suggested fields:
- type
- message
- phase
- progress
- createdAt
- metadata

### `payments`
Suggested fields:
- userId
- stripeCustomerId
- checkoutSessionId
- paymentStatus
- productKey
- createdAt
- updatedAt

### `subscriptions`
If using subscriptions or entitlements.

### `usage`
Track rate limiting / quotas / scan consumption.

---

## Authentication Requirements

Use Firebase Authentication with Google sign-in.

### Rules
- anonymous scan creation is allowed
- premium details require authenticated user
- saved history requires authenticated user
- linking anonymous scan to signed-in user must be supported
- protect server routes requiring a verified user
- use Firebase Admin SDK on secure server paths
- never trust raw client claims without verification

---

## Payment Requirements

Use Stripe for paid access to deeper details.

### Billing behavior
After the user gets a basic report:
- show locked premium sections
- CTA to unlock full details
- if user is not signed in, require Google sign-in first
- then create Stripe checkout session
- after successful payment, mark entitlements in Firestore
- unlock premium details in UI and API

### Premium examples
Premium-only content may include:
- expanded remediation steps
- full evidence payloads
- deeper category explanations
- longer report history
- export/report download
- enhanced scan retention
- extended findings beyond the free tier

### Payment implementation requirements
- use secure server-side Stripe session creation
- verify Stripe webhook events
- do not trust client redirect alone
- write billing state changes to Firestore
- document products/prices/env vars in `HISTORY.md`

---

## API Requirements

Implement clean API routes or route handlers.

Suggested endpoints:

### Public / mixed
- `POST /api/scans` -> create a new scan
- `GET /api/scans/:id` -> get scan summary
- `GET /api/scans/:id/findings` -> get filtered findings
- `GET /api/scans/:id/events` -> progress feed or polling data

### Auth-required
- `GET /api/me/scans` -> current user's scan history
- `POST /api/scans/:id/claim` -> attach anonymous scan to logged-in user
- `POST /api/billing/checkout` -> create checkout session
- `POST /api/billing/webhook` -> Stripe webhook endpoint

### API standards
- validate all inputs
- return typed structured responses
- include useful error codes/messages
- do not leak internals
- use rate limiting where relevant

---

## Scan History Requirements

The product must include a history concept for users.

### Product-level scan history
Signed-in users should be able to:
- view previous scans
- reopen a scan
- see creation date
- see target domain
- see summary scores
- see current subscription access level for premium details

### Anonymous behavior
Anonymous users may see the current scan only.
Persistent history requires login.

---

## Required Repository History File

There must be a root file called:

- `HISTORY.md`

This file is **mandatory** and must be updated on every meaningful code change.

Its purpose is to track what the coding agent changed, so future runs have context.

### Rules for `HISTORY.md`
1. Append-only. Do not delete old entries unless explicitly asked.
2. Add a new entry after each completed task or logical batch of related changes.
3. Be specific and practical.
4. Mention files changed.
5. Mention schema changes.
6. Mention env var changes.
7. Mention manual follow-up steps if any.
8. Mention breaking changes explicitly.
9. Mention migrations or backfills if needed.
10. Keep entries concise but informative.

### Required entry format

```md
## YYYY-MM-DD HH:mm - Short Title

### Summary
- What was implemented or changed

### Files Changed
- path/to/file1
- path/to/file2

### Data / Schema
- Firestore collections or fields added/changed
- indexes needed
- migration/backfill notes if any

### Env Changes
- NEW_ENV_VAR: why it was added
- UPDATED_ENV_VAR: what changed

### Routes / APIs
- Added/changed endpoints

### Notes
- important implementation notes
- follow-up tasks
- known limitations

### Breaking Changes
- None
```

If there are no breaking changes, explicitly write:
- `None`

---

## Design Rules

The design must come from:
- `page1.html`
- `page2.html`

### Design instructions
- match layout structure closely
- match spacing rhythm
- match visual tone
- keep the clean SaaS dashboard style
- do not replace the design system unless explicitly asked
- convert static HTML into reusable React/Next components
- preserve responsive behavior and accessibility
- extract reusable UI pieces such as:
  - layout shell
  - input section
  - score widgets
  - tabs
  - finding cards
  - sidebar panels
  - CTA blocks

---

## Quality Requirements

### Code quality
- strict TypeScript when possible
- reusable components
- server/client boundaries respected
- no duplicated business logic
- small focused modules
- useful comments only where necessary

### Security
- sanitize inputs
- protect billing/auth routes
- avoid SSRF risks in scanning logic
- block internal/private address scanning unless explicitly allowed and safely handled
- validate domains carefully
- use timeouts and abort controllers
- store secrets only in env vars
- verify webhook signatures
- verify Firebase auth tokens server-side

### Performance
- avoid blocking the request thread
- do not perform full scan work in frontend
- cache safe derived data when helpful
- avoid unnecessary browser runs when HTTP checks are enough

### UX
- meaningful loading states
- empty states
- error states
- partial results while scan is running
- clear CTAs for login and upgrade

### Observability
- structured logs
- scan/job error logging
- category-level failure visibility
- useful debugging information in server logs, not exposed to end users

---

## Environment Variables

Use env vars for all secrets and environment-specific values.

Typical env vars may include:
- `FIREBASE_PROJECT_ID`
- `FIREBASE_CLIENT_EMAIL`
- `FIREBASE_PRIVATE_KEY`
- `NEXT_PUBLIC_FIREBASE_API_KEY`
- `NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN`
- `NEXT_PUBLIC_FIREBASE_PROJECT_ID`
- `NEXT_PUBLIC_FIREBASE_APP_ID`
- `NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID`
- `REDIS_URL`
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY`
- `STRIPE_PRICE_ID_PREMIUM`
- `NEXT_PUBLIC_APP_URL`

Document additions/changes in `HISTORY.md`.

---

## Implementation Priority

When building from scratch, use this order unless the user says otherwise:

1. project scaffolding
2. design integration from `page1.html` and `page2.html`
3. Firebase setup
4. scan creation flow
5. BullMQ/Redis background jobs
6. security scan implementation
7. live results page
8. Google auth
9. scan history
10. Stripe payment / premium gating
11. SEO and performance scan expansion
12. refinements, hardening, polish

---

## Deliverable Expectations Per Task

For each coding task:
1. implement the requested change
2. keep architecture clean
3. update `HISTORY.md`
4. avoid unrelated refactors unless necessary
5. if you must make an assumption, choose a reasonable production-safe default
6. if something blocks implementation, leave a clear TODO in code and note it in `HISTORY.md`

---

## Definition of Done

A task is only done when:
- code is implemented
- relevant routes/components/services are wired together
- errors are handled
- `HISTORY.md` is updated
- feature is reasonably production-ready for its current scope

---

## Final Reminder

You are building a real product, not a mockup and not a toy demo.

Prioritize:
- correctness
- clean architecture
- async scanning
- production-safe behavior
- design fidelity to `page1.html` and `page2.html`
- Firebase for data/auth
- Google login after results
- Stripe-based premium unlock flow
- mandatory `HISTORY.md` updates on every meaningful change
