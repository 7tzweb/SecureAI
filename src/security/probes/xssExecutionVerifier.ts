import type { BrowserContextOptions } from "playwright";
import { maskSecretPreview } from "@/security/findings";

export type XssExecutionSignal = {
  type: "dialog" | "console" | "dom" | "window-marker" | "dom-mutation-marker" | "callback";
  value: string;
  timestamp: string;
};

export type XssExecutionVerification = {
  marker: string;
  payload: string;
  sanitizedPayload: string;
  url: string;
  status: number | null;
  executed: boolean;
  signals: XssExecutionSignal[];
  domState: {
    bodyTextIncludesMarker: boolean;
    domAttributeMarker: boolean;
    windowMarker: boolean;
    mutationSignals: number;
  } | null;
};

function randomMarkerSuffix() {
  return Math.random().toString(36).slice(2, 9);
}

export function createXssMarker(scanId = "scan") {
  return `fixnx_xss_${scanId.replace(/[^a-z0-9_-]/gi, "_")}_${Date.now()}_${randomMarkerSuffix()}`;
}

export function controlledXssPayloads(marker: string) {
  return [
    {
      kind: "window-marker",
      value: `"><svg data-fixnx-xss="${marker}" onload="window.__FIXNX_XSS_MARKER__='${marker}';console.log('${marker}')"></svg>`,
    },
    {
      kind: "image-onerror",
      value: `<img src=x data-fixnx-xss="${marker}" onerror="window.__FIXNX_XSS_MARKER__='${marker}';console.log('${marker}')">`,
    },
    {
      kind: "dialog",
      value: `"><svg data-fixnx-xss="${marker}" onload="alert('${marker}')"></svg>`,
    },
  ];
}

export async function verifyXssExecution(input: {
  url: string;
  marker: string;
  payload: string;
  contextOptions?: BrowserContextOptions;
  localStorage?: Record<string, string>;
  waitMs?: number;
}) {
  const signals: XssExecutionSignal[] = [];
  let status: number | null = null;
  let domState: XssExecutionVerification["domState"] = null;
  let browser: Awaited<ReturnType<(typeof import("playwright"))["chromium"]["launch"]>> | null = null;

  try {
    const { chromium } = await import("playwright");
    browser = await chromium.launch({
      headless: true,
      args: ["--disable-dev-shm-usage", "--no-sandbox"],
    });
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      javaScriptEnabled: true,
      userAgent: "fixnx/1.0 xss-verifier (+https://example.invalid/cyberaudit)",
      ...input.contextOptions,
    });
    const page = await context.newPage();

    page.on("dialog", (dialog) => {
      const message = dialog.message();
      if (message.includes(input.marker)) {
        signals.push({
          type: "dialog",
          value: message,
          timestamp: new Date().toISOString(),
        });
      }
      void dialog.dismiss().catch(() => undefined);
    });
    page.on("console", (message) => {
      const text = message.text();
      if (text.includes(input.marker)) {
        signals.push({
          type: "console",
          value: text,
          timestamp: new Date().toISOString(),
        });
      }
    });

    await page.addInitScript((marker) => {
      (window as Window & { __fixnxXssSignals?: Array<{ type: string; marker: string; time: number }> }).__fixnxXssSignals = [];
      Object.defineProperty(window as Window & { __FIXNX_XSS_MARKER__?: string | null }, "__FIXNX_XSS_MARKER__", {
        configurable: true,
        writable: true,
        value: null,
      });
      window.addEventListener("DOMContentLoaded", () => {
        const observer = new MutationObserver(() => {
          if (document.documentElement.innerHTML.includes(marker)) {
            (window as Window & { __fixnxXssSignals?: Array<{ type: string; marker: string; time: number }> }).__fixnxXssSignals?.push({
              type: "dom-mutation-marker",
              marker,
              time: Date.now(),
            });
          }
        });
        observer.observe(document.documentElement, {
          childList: true,
          subtree: true,
          attributes: true,
        });
      });
    }, input.marker);

    if (input.localStorage && Object.keys(input.localStorage).length > 0) {
      await page.addInitScript((entries) => {
        for (const [key, value] of Object.entries(entries as Record<string, string>)) {
          window.localStorage.setItem(key, value);
        }
      }, input.localStorage);
    }

    const response = await page.goto(input.url, {
      waitUntil: "domcontentloaded",
      timeout: 6_000,
    }).catch(() => null);
    status = response?.status() ?? null;
    await page.waitForTimeout(input.waitMs ?? 800).catch(() => undefined);

    domState = await page
      .evaluate((marker) => {
        const signals = (window as Window & { __fixnxXssSignals?: unknown[] }).__fixnxXssSignals ?? [];
        return {
          bodyTextIncludesMarker: document.body.innerText.includes(marker),
          domAttributeMarker: Boolean(document.querySelector(`[data-fixnx-xss="${marker}"]`)),
          windowMarker: (window as Window & { __FIXNX_XSS_MARKER__?: string | null }).__FIXNX_XSS_MARKER__ === marker,
          mutationSignals: Array.isArray(signals) ? signals.length : 0,
        };
      }, input.marker)
      .catch(() => null);

    if (domState?.windowMarker) {
      signals.push({
        type: "window-marker",
        value: input.marker,
        timestamp: new Date().toISOString(),
      });
    }
    if (domState?.domAttributeMarker && domState.windowMarker) {
      signals.push({
        type: "dom",
        value: input.marker,
        timestamp: new Date().toISOString(),
      });
    }
    if (domState && domState.mutationSignals > 0 && domState.windowMarker) {
      signals.push({
        type: "dom-mutation-marker",
        value: `${domState.mutationSignals} mutation signal(s)`,
        timestamp: new Date().toISOString(),
      });
    }

    await context.close().catch(() => undefined);
  } finally {
    await browser?.close().catch(() => undefined);
  }

  return {
    marker: maskSecretPreview(input.marker, 12, 6),
    payload: input.payload,
    sanitizedPayload: input.payload.replaceAll(input.marker, maskSecretPreview(input.marker, 12, 6)),
    url: input.url,
    status,
    executed: signals.some((signal) => ["dialog", "console", "window-marker", "dom", "dom-mutation-marker", "callback"].includes(signal.type)),
    signals,
    domState,
  } satisfies XssExecutionVerification;
}
