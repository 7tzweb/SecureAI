# CyberAudit

CyberAudit is a production-oriented Next.js application for website auditing across security, SEO, and performance. It creates scans immediately, processes categories asynchronously, streams partial results to the report page, keeps fix details behind Google sign-in, and enforces a free 5-scan quota per signed-in account with a $9 unlimited upgrade path.

## Stack

- Next.js 16 App Router
- TypeScript
- Tailwind CSS 4
- Firebase Authentication + Firebase Admin + Firestore
- Redis + BullMQ
- Stripe

## Local Development

1. Install dependencies:

```bash
npm install
```

2. Copy environment variables:

```bash
cp .env.example .env.local
```

3. Start the web app:

```bash
npm run dev
```

4. If you configured `REDIS_URL`, run the worker in a second shell:

```bash
npm run worker
```

## Fallback Behavior

The app is built to run locally even before external services are configured.

- Without Firebase Admin credentials, storage falls back to the local file-backed repository.
- Without Redis, scan jobs run through an in-process async queue.
- Without Firebase client credentials, Google login buttons remain disabled.
- Without a Firebase service account file, Google sessions still work through Firebase token verification, but Firestore stays disabled.
- Without Stripe configuration, quota upgrades remain disabled.

These fallbacks are for development convenience only. Production deployment should use Firestore, Redis/BullMQ, Firebase Auth, and Stripe.

## Environment Variables

See `.env.example` for the full list.

- `NEXT_PUBLIC_APP_URL`
- `NEXT_PUBLIC_FIREBASE_API_KEY`
- `NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN`
- `NEXT_PUBLIC_FIREBASE_PROJECT_ID`
- `NEXT_PUBLIC_FIREBASE_APP_ID`
- `NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID`
- `VITE_FIREBASE_API_KEY`
- `VITE_FIREBASE_AUTH_DOMAIN`
- `VITE_FIREBASE_PROJECT_ID`
- `VITE_FIREBASE_STORAGE_BUCKET`
- `VITE_FIREBASE_MESSAGING_SENDER_ID`
- `VITE_FIREBASE_APP_ID`
- `VITE_FIREBASE_MEASUREMENT_ID`
- `VITE_API_BASE_URL`
- `FIREBASE_PROJECT_ID`
- `FIREBASE_SERVICE_ACCOUNT_PATH`
- `FIREBASE_CLIENT_EMAIL`
- `FIREBASE_PRIVATE_KEY`
- `GOOGLE_OAUTH_CLIENT_ID`
- `GOOGLE_OAUTH_CLIENT_SECRET`
- `SESSION_SECRET`
- `REDIS_URL`
- `STRIPE_PUBLIC_KEY`
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY`
- `STRIPE_PRICE_ID_PREMIUM`
- `STRIPE_SCAN_PLAN_PRICE_USD`
- `OPENAI_API_KEY`

## Routes

Pages:

- `/`
- `/scans/[scanId]`
- `/history`

API:

- `POST /api/scans`
- `GET /api/scans/[scanId]`
- `GET /api/scans/[scanId]/findings`
- `GET /api/scans/[scanId]/events`
- `POST /api/scans/[scanId]/claim`
- `GET /api/me/scans`
- `GET /api/me/usage`
- `GET|POST|DELETE /api/auth/session`
- `POST /api/billing/checkout`
- `POST /api/billing/confirm`
- `POST /api/billing/webhook`

## Verification

The current codebase passes:

```bash
npm run lint
npm run typecheck
npm run build
```
