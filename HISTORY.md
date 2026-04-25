# HISTORY.md

Active history only. Older detailed entries were moved to:

- `docs/archive/history/HISTORY-2026-04-24-full.md`

This file should stay short and focus on the current product baseline plus the most recent meaningful changes.

## Current Baseline - 2026-04-24

- Next.js + TypeScript application for live website audits across Security, SEO, and Performance
- Anonymous users can start scans and view the main report
- Google sign-in is required to unlock fix guidance and link scans into account history
- Signed-in users receive 3 free scans
- Additional usage is sold as a PayPal credit pack: 30 scans for $4.90
- Shared header, report workspace, and history screens are live
- Firestore is the primary production store when configured
- `.cyberaudit/runtime-store.json` is the local file-backed fallback store
- Redis + BullMQ are used when configured; otherwise the local async queue is used

## 2026-04-24 - Usage Cleanup

### Summary

- Replaced the oversized `agent.md` with a short current-context version
- Archived the full legacy change log out of the active `HISTORY.md`
- Prepared the repo for lower-context work by keeping active project docs compact

### Files Changed

- `agent.md`
- `HISTORY.md`
- `docs/archive/history/HISTORY-2026-04-24-full.md`

### Notes

- The archive is still available for manual reference, but it is no longer the active working document
- The active project docs should remain short enough to read quickly during normal work
