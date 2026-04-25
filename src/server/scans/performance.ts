import { type FindingStatus, type Severity } from "@/lib/types";
import { applyPremiumGating, computeScore } from "@/lib/utils";
import {
  type UrlProbe,
  loadAuditArtifacts,
  sumKnownBytes,
} from "@/server/scans/artifacts";
import { createFinding, isLikelyEdgeInterstitial } from "@/server/scans/helpers";
import { type CategoryScanResult, type NormalizedTarget } from "@/server/scans/types";

const limitedPerformanceChecks = [
  ["ttfb", "TTFB"],
  ["html-response-time", "HTML response time"],
  ["total-request-count", "Total request count"],
  ["total-page-weight", "Total page weight"],
  ["javascript-bundle-weight", "JavaScript bundle weight"],
  ["css-bundle-weight", "CSS bundle weight"],
  ["unoptimized-images", "Unoptimized images"],
  ["modern-image-formats", "Modern image formats"],
  ["image-dimensions-vs-declared-size", "Image dimensions vs declared size"],
  ["lazy-loading", "Lazy loading"],
  ["compression-enabled", "Compression enabled"],
  ["cache-headers", "Cache headers"],
  ["render-blocking-resources", "Render-blocking resources"],
  ["third-party-script-weight", "Third-party script weight"],
  ["redirect-chains", "Redirect chains"],
  ["fonts-optimization", "Fonts optimization"],
  ["dom-size", "DOM size"],
  ["main-thread-pressure-hint", "Main thread pressure hint"],
  ["lcp-style-hint", "LCP-style hint"],
  ["cls-style-hint", "CLS-style hint"],
] as const;

type ImageDimensionSample = {
  url: string;
  width: number;
  height: number;
};

function buildPerformanceCheck(input: {
  checkKey: string;
  title: string;
  status: FindingStatus;
  severity: Severity;
  shortDescription: string;
  whyItMatters: string;
  recommendation: string;
  evidence?: Record<string, unknown>;
  premiumOnly?: boolean;
}) {
  return createFinding({
    ...input,
    category: "performance",
  });
}

function formatBytes(bytes: number) {
  if (bytes >= 1_000_000) {
    return `${(bytes / 1_000_000).toFixed(2)} MB`;
  }
  if (bytes >= 1_000) {
    return `${Math.round(bytes / 1_000)} KB`;
  }
  return `${bytes} B`;
}

function resourceProbeMap(probes: UrlProbe[]) {
  return new Map(probes.map((probe) => [probe.url, probe]));
}

function lowerBetterStatus(
  value: number,
  passMax: number,
  warningMax: number,
  passSeverity: Severity = "info",
  warningSeverity: Severity = "low",
  failSeverity: Severity = "medium",
) {
  if (value <= passMax) {
    return { status: "pass" as const, severity: passSeverity };
  }
  if (value <= warningMax) {
    return { status: "warning" as const, severity: warningSeverity };
  }
  return { status: "fail" as const, severity: failSeverity };
}

function countHeaderCaching(probes: UrlProbe[]) {
  return probes.filter((probe) => {
    const cacheControl = probe.cacheControl?.toLowerCase() ?? "";
    return (
      cacheControl.includes("max-age=") ||
      cacheControl.includes("immutable") ||
      Boolean(probe.etag) ||
      Boolean(probe.lastModified)
    );
  }).length;
}

async function fetchBinarySample(url: string, maxBytes = 64_000) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8_000);
    const response = await fetch(url, {
      headers: {
        "user-agent": "CyberAudit/1.0 (+https://example.invalid/cyberaudit)",
        range: `bytes=0-${maxBytes - 1}`,
      },
      redirect: "follow",
      signal: controller.signal,
    });
    clearTimeout(timeout);
    if (!response.ok) {
      return null;
    }
    return new Uint8Array(await response.arrayBuffer());
  } catch {
    return null;
  }
}

function parsePngDimensions(bytes: Uint8Array): ImageDimensionSample | null {
  if (bytes.length < 24) {
    return null;
  }
  const signature = [137, 80, 78, 71, 13, 10, 26, 10];
  if (!signature.every((value, index) => bytes[index] === value)) {
    return null;
  }
  const width = new DataView(bytes.buffer).getUint32(16);
  const height = new DataView(bytes.buffer).getUint32(20);
  return { url: "", width, height };
}

function parseGifDimensions(bytes: Uint8Array): ImageDimensionSample | null {
  if (bytes.length < 10) {
    return null;
  }
  const header = String.fromCharCode(...bytes.slice(0, 6));
  if (!["GIF87a", "GIF89a"].includes(header)) {
    return null;
  }
  const view = new DataView(bytes.buffer);
  return {
    url: "",
    width: view.getUint16(6, true),
    height: view.getUint16(8, true),
  };
}

function parseJpegDimensions(bytes: Uint8Array): ImageDimensionSample | null {
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) {
    return null;
  }

  let offset = 2;
  while (offset + 9 < bytes.length) {
    if (bytes[offset] !== 0xff) {
      offset += 1;
      continue;
    }

    const marker = bytes[offset + 1];
    const length = (bytes[offset + 2] << 8) + bytes[offset + 3];
    if ([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker)) {
      const height = (bytes[offset + 5] << 8) + bytes[offset + 6];
      const width = (bytes[offset + 7] << 8) + bytes[offset + 8];
      return { url: "", width, height };
    }
    offset += 2 + length;
  }

  return null;
}

function parseWebpDimensions(bytes: Uint8Array): ImageDimensionSample | null {
  if (bytes.length < 30) {
    return null;
  }
  const riff = String.fromCharCode(...bytes.slice(0, 4));
  const webp = String.fromCharCode(...bytes.slice(8, 12));
  if (riff !== "RIFF" || webp !== "WEBP") {
    return null;
  }

  const chunk = String.fromCharCode(...bytes.slice(12, 16));
  const view = new DataView(bytes.buffer);
  if (chunk === "VP8X" && bytes.length >= 30) {
    const width = 1 + bytes[24] + (bytes[25] << 8) + (bytes[26] << 16);
    const height = 1 + bytes[27] + (bytes[28] << 8) + (bytes[29] << 16);
    return { url: "", width, height };
  }
  if (chunk === "VP8 " && bytes.length >= 30) {
    const width = view.getUint16(26, true) & 0x3fff;
    const height = view.getUint16(28, true) & 0x3fff;
    return { url: "", width, height };
  }
  if (chunk === "VP8L" && bytes.length >= 25) {
    const bits = view.getUint32(21, true);
    const width = (bits & 0x3fff) + 1;
    const height = ((bits >> 14) & 0x3fff) + 1;
    return { url: "", width, height };
  }

  return null;
}

function parseImageDimensions(bytes: Uint8Array, url: string) {
  const parserResults = [
    parsePngDimensions(bytes),
    parseGifDimensions(bytes),
    parseJpegDimensions(bytes),
    parseWebpDimensions(bytes),
  ];

  const parsed = parserResults.find((result) => Boolean(result));
  return parsed ? { ...parsed, url } : null;
}

export async function runPerformanceScan(
  target: NormalizedTarget,
): Promise<CategoryScanResult> {
  const artifacts = await loadAuditArtifacts(target);
  const primaryAttempt = artifacts.context.primary;
  const primaryPage = artifacts.primaryPage;

  if (primaryAttempt && isLikelyEdgeInterstitial(primaryAttempt)) {
    const findings = limitedPerformanceChecks.map(([checkKey, title]) =>
      buildPerformanceCheck({
        checkKey,
        title,
        status: "info",
        severity: "info",
        shortDescription:
          "This check was skipped because the sampled response looked like an edge interstitial or bot-protection page instead of the site's application payload.",
        whyItMatters:
          "Performance checks need the actual page and resource graph to measure transfer size, render blockers, image handling, and browser workload.",
        recommendation:
          "Run the scan from an environment that can fetch the real page response before treating this performance check as pass or fail.",
        evidence: {
          checkedUrl: primaryAttempt.finalUrl,
          expectedLocation: "Public page HTML and resource graph",
          summary:
            "The scanner reached an edge interstitial or challenge response, so the underlying application performance could not be measured reliably.",
          statusCode: primaryAttempt.status,
        },
      }),
    );
    return {
      findings: applyPremiumGating(findings),
      score: computeScore(findings),
    };
  }

  if (!primaryAttempt || !primaryPage) {
    throw new Error("Unable to fetch the target website.");
  }

  const findings = [];
  const probeByUrl = resourceProbeMap(artifacts.resourceProbes);
  const scripts = primaryPage.resources.filter((resource) => resource.kind === "script");
  const stylesheets = primaryPage.resources.filter((resource) => resource.kind === "stylesheet");
  const images = primaryPage.images;
  const iframes = primaryPage.resources.filter((resource) => resource.kind === "iframe");
  const fonts = artifacts.resourceProbes.filter(
    (probe) =>
      probe.contentType?.toLowerCase().includes("font") ||
      /\.(woff2?|ttf|eot|otf)(\?|$)/i.test(probe.url),
  );
  const renderBlockingScripts = scripts.filter(
    (resource) => resource.location.path?.startsWith("html > head >"),
  );
  const requestCount = primaryPage.resources.length + 1;
  const totalKnownWeight = primaryPage.htmlBytes + sumKnownBytes(artifacts.resourceProbes);
  const jsProbes = scripts
    .map((resource) => probeByUrl.get(resource.url))
    .filter((probe): probe is UrlProbe => Boolean(probe));
  const cssProbes = stylesheets
    .map((resource) => probeByUrl.get(resource.url))
    .filter((probe): probe is UrlProbe => Boolean(probe));
  const imageProbes = images
    .map((resource) => ({
      resource,
      probe: probeByUrl.get(resource.url) ?? null,
    }))
    .filter((entry) => entry.probe !== null)
    .map((entry) => ({ resource: entry.resource, probe: entry.probe as UrlProbe }));
  const externalScriptEntries = scripts
    .filter((resource) => !resource.internal)
    .map((resource) => ({
      resource,
      probe: probeByUrl.get(resource.url) ?? null,
    }))
    .filter((entry) => entry.probe !== null)
    .map((entry) => ({ resource: entry.resource, probe: entry.probe as UrlProbe }));

  const ttfbStatus = lowerBetterStatus(primaryAttempt.durationMs, 800, 1_500, "info", "low", "high");
  findings.push(
    buildPerformanceCheck({
      checkKey: "ttfb",
      title: "TTFB",
      ...ttfbStatus,
      shortDescription: `The main document responded in ${primaryAttempt.durationMs} ms.`,
      whyItMatters:
        "Time to first byte strongly influences perceived speed and the remaining budget for rendering.",
      recommendation:
        ttfbStatus.status === "pass"
          ? "Keep backend, caching, and edge delivery tuned for low latency."
          : "Profile origin latency, caching, and any expensive application work on the initial request path.",
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        expectedLocation: "Initial document response time",
        summary: "Measured from request start until response headers were received.",
        ttfbMs: primaryAttempt.durationMs,
      },
    }),
  );

  const htmlResponseStatus = lowerBetterStatus(primaryAttempt.totalDurationMs, 1_500, 3_000, "info", "low", "high");
  findings.push(
    buildPerformanceCheck({
      checkKey: "html-response-time",
      title: "HTML response time",
      ...htmlResponseStatus,
      shortDescription: `The main HTML finished transferring in ${primaryAttempt.totalDurationMs} ms.`,
      whyItMatters:
        "Slow HTML delivery delays parsing, rendering, and every downstream asset request.",
      recommendation:
        htmlResponseStatus.status === "pass"
          ? "Keep HTML delivery lightweight and cache-friendly."
          : "Reduce server work and document size so the HTML can finish loading sooner.",
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        expectedLocation: "Main HTML response transfer time",
        summary: "Measured from request start until the HTML body finished downloading.",
        totalResponseMs: primaryAttempt.totalDurationMs,
      },
    }),
  );

  const requestCountStatus = lowerBetterStatus(requestCount, 35, 70, "info", "low", "high");
  findings.push(
    buildPerformanceCheck({
      checkKey: "total-request-count",
      title: "Total request count",
      ...requestCountStatus,
      shortDescription: `The initial HTML references ${requestCount} document and asset requests.`,
      whyItMatters:
        "A high request count increases connection overhead and slows both cold and warm navigations.",
      recommendation:
        requestCountStatus.status === "pass"
          ? "Keep the request graph lean as the page evolves."
          : "Reduce unnecessary scripts, stylesheets, images, and embeds in the first view.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: "HTML-discovered scripts, stylesheets, images, iframes, and forms",
        summary: "Counted from the primary page markup without executing client-side JavaScript.",
        requestCount,
      },
    }),
  );

  const totalWeightStatus = lowerBetterStatus(totalKnownWeight, 1_500_000, 3_000_000, "info", "low", "high");
  findings.push(
    buildPerformanceCheck({
      checkKey: "total-page-weight",
      title: "Total page weight",
      ...totalWeightStatus,
      shortDescription: `Known document and asset weight is ${formatBytes(totalKnownWeight)}.`,
      whyItMatters:
        "Heavy pages increase download time, parsing time, and cost on slower networks and mobile devices.",
      recommendation:
        totalWeightStatus.status === "pass"
          ? "Keep the initial page weight controlled as assets change."
          : "Compress, defer, and trim the initial HTML and referenced assets.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: "Main HTML plus sampled asset Content-Length values",
        summary: "Calculated from the main HTML bytes plus sampled asset sizes exposed by the server.",
        totalKnownWeightBytes: totalKnownWeight,
      },
    }),
  );

  const totalJsBytes = sumKnownBytes(jsProbes);
  const jsStatus = lowerBetterStatus(totalJsBytes, 300_000, 700_000, "info", "low", "high");
  findings.push(
    buildPerformanceCheck({
      checkKey: "large-javascript-bundle",
      title: "JavaScript bundle weight",
      ...jsStatus,
      shortDescription: `Sampled JavaScript weight is ${formatBytes(totalJsBytes)} across ${scripts.length} script tags.`,
      whyItMatters:
        "Large JavaScript bundles increase parse, compile, and main-thread execution cost.",
      recommendation:
        jsStatus.status === "pass"
          ? "Keep JavaScript payloads lean and defer non-critical work."
          : "Reduce, split, or defer JavaScript that is not needed for the initial view.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: "script[src] resources from the initial HTML",
        summary: "Calculated from sampled script asset sizes exposed by the server.",
        totalJsBytes,
        scriptCount: scripts.length,
      },
    }),
  );

  const totalCssBytes = sumKnownBytes(cssProbes);
  const cssStatus = lowerBetterStatus(totalCssBytes, 150_000, 300_000, "info", "low", "high");
  findings.push(
    buildPerformanceCheck({
      checkKey: "large-css-bundle",
      title: "CSS bundle weight",
      ...cssStatus,
      shortDescription: `Sampled stylesheet weight is ${formatBytes(totalCssBytes)} across ${stylesheets.length} stylesheets.`,
      whyItMatters:
        "Large CSS payloads slow the critical rendering path and can delay first paint.",
      recommendation:
        cssStatus.status === "pass"
          ? "Keep stylesheets compact and scoped to what the page needs."
          : "Trim or split stylesheets and inline only genuinely critical CSS.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: 'link[rel="stylesheet"] resources from the initial HTML',
        summary: "Calculated from sampled stylesheet asset sizes exposed by the server.",
        totalCssBytes,
        stylesheetCount: stylesheets.length,
      },
    }),
  );

  const largeImages = imageProbes.filter(
    ({ probe }) => (probe.contentLength ?? 0) >= 350_000,
  );
  const hugeImages = imageProbes.filter(({ probe }) => (probe.contentLength ?? 0) >= 1_000_000);
  const imageWeightStatus =
    largeImages.length === 0
      ? { status: "pass" as const, severity: "info" as const }
      : hugeImages.length > 0 || largeImages.length > 3
        ? { status: "fail" as const, severity: "medium" as const }
        : { status: "warning" as const, severity: "low" as const };
  findings.push(
    buildPerformanceCheck({
      checkKey: "unoptimized-images",
      title: "Unoptimized images",
      ...imageWeightStatus,
      shortDescription:
        largeImages.length === 0
          ? "No sampled images exceeded the large-image threshold."
          : `${largeImages.length} sampled images are larger than 350 KB.`,
      whyItMatters:
        "Heavy images increase transfer cost and often become the dominant factor in perceived load speed.",
      recommendation:
        largeImages.length === 0
          ? "Keep optimizing new images as they are added."
          : "Compress or resize large images and serve appropriately sized variants where possible.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: "img[src] resources from the initial HTML",
        summary:
          largeImages.length === 0
            ? "No large sampled images were detected."
            : "Some sampled images are significantly larger than typical first-view budgets.",
        largeImages: largeImages.length,
        locations: largeImages.slice(0, 8).map(({ resource, probe }, index) => ({
          ...resource.location,
          label: `Image ${index + 1}`,
          note: `Approximate file size ${formatBytes(probe.contentLength ?? 0)}.`,
        })),
      },
    }),
  );

  const modernImageCount = imageProbes.filter(({ probe }) =>
    /(image\/webp|image\/avif|image\/svg\+xml)/i.test(probe.contentType ?? "") ||
    /\.(webp|avif|svg)(\?|$)/i.test(probe.url),
  ).length;
  const modernImageStatus =
    imageProbes.length === 0 || modernImageCount / Math.max(imageProbes.length, 1) >= 0.25
      ? { status: "pass" as const, severity: "info" as const }
      : { status: "warning" as const, severity: "low" as const };
  findings.push(
    buildPerformanceCheck({
      checkKey: "modern-image-formats",
      title: "Modern image formats",
      ...modernImageStatus,
      shortDescription:
        imageProbes.length === 0
          ? "No sampled images were available to evaluate."
          : `${modernImageCount} of ${imageProbes.length} sampled images use modern formats such as WebP or AVIF.`,
      whyItMatters:
        "Modern image formats typically reduce transfer size compared with older raster formats.",
      recommendation:
        imageProbes.length === 0 || modernImageStatus.status === "pass"
          ? "Keep using efficient image formats where browser support allows."
          : "Prefer WebP or AVIF for heavy photographic assets when browser support permits.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: "Sampled image resource content types and URLs",
        summary:
          imageProbes.length === 0
            ? "No image probes were available."
            : "Calculated from sampled image resource formats.",
        modernImageCount,
        sampledImages: imageProbes.length,
      },
    }),
  );

  const dimensionSamples = await Promise.all(
    images
      .filter((image) => image.declaredWidth && image.declaredHeight)
      .slice(0, 6)
      .map(async (image) => {
        const bytes = await fetchBinarySample(image.url);
        if (!bytes) {
          return null;
        }
        const metadata = parseImageDimensions(bytes, image.url);
        if (!metadata) {
          return null;
        }
        return {
          image,
          metadata,
        };
      }),
  );
  const oversizedImages = dimensionSamples
    .filter((sample): sample is NonNullable<typeof sample> => Boolean(sample))
    .filter(
      (sample) =>
        Boolean(sample.image.declaredWidth) &&
        Boolean(sample.image.declaredHeight) &&
        (sample.metadata.width / Number(sample.image.declaredWidth) > 2.5 ||
          sample.metadata.height / Number(sample.image.declaredHeight) > 2.5),
    );
  const dimensionStatus =
    dimensionSamples.filter(Boolean).length === 0
      ? { status: "info" as const, severity: "info" as const }
      : oversizedImages.length === 0
        ? { status: "pass" as const, severity: "info" as const }
        : oversizedImages.length > 2
          ? { status: "fail" as const, severity: "medium" as const }
          : { status: "warning" as const, severity: "low" as const };
  findings.push(
    buildPerformanceCheck({
      checkKey: "image-dimensions-vs-render-size",
      title: "Image dimensions vs declared size",
      ...dimensionStatus,
      shortDescription:
        dimensionSamples.filter(Boolean).length === 0
          ? "No sampled images exposed declared dimensions suitable for comparison."
          : oversizedImages.length === 0
            ? "Sampled images are reasonably aligned with their declared dimensions."
            : `${oversizedImages.length} sampled images are much larger than their declared dimensions.`,
      whyItMatters:
        "Images that are significantly larger than their rendered or declared size waste bandwidth and decode time.",
      recommendation:
        oversizedImages.length === 0
          ? "Keep serving images close to the size they are displayed."
          : "Serve images closer to the actual display size or use responsive image variants.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: "Sampled img[src] resources with width/height attributes",
        summary:
          dimensionSamples.filter(Boolean).length === 0
            ? "This check used a limited binary sample and only compared images with declared width/height attributes."
            : "This check used sampled image headers and compared natural dimensions with declared width/height attributes.",
        oversizedImages: oversizedImages.length,
        locations: oversizedImages.map((sample, index) => ({
          ...sample.image.location,
          label: `Image ${index + 1}`,
          note: `Natural size ${sample.metadata.width}x${sample.metadata.height}; declared ${sample.image.declaredWidth}x${sample.image.declaredHeight}.`,
        })),
      },
    }),
  );

  const lazyCandidates = [...images.slice(2), ...iframes];
  const missingLazy = lazyCandidates.filter((resource) => resource.loading !== "lazy");
  const lazyStatus =
    missingLazy.length === 0
      ? { status: "pass" as const, severity: "info" as const }
      : missingLazy.length > 5
        ? { status: "fail" as const, severity: "medium" as const }
        : { status: "warning" as const, severity: "low" as const };
  findings.push(
    buildPerformanceCheck({
      checkKey: "lazy-loading",
      title: "Lazy loading",
      ...lazyStatus,
      shortDescription:
        missingLazy.length === 0
          ? "Sampled below-the-fold candidates expose lazy loading hints."
          : `${missingLazy.length} sampled image or iframe candidates are missing lazy loading hints.`,
      whyItMatters:
        "Lazy loading reduces transfer and decode cost for content that is not immediately visible.",
      recommendation:
        missingLazy.length === 0
          ? "Keep using lazy loading for non-critical images and embeds."
          : "Add `loading=\"lazy\"` to non-critical images and iframes where appropriate.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: 'img/iframe elements after the first two images should prefer loading="lazy"',
        summary:
          missingLazy.length === 0
            ? "The sampled non-critical media elements expose lazy loading hints."
            : "Some sampled media elements are missing lazy loading hints.",
        missingLazy: missingLazy.length,
        locations: missingLazy.slice(0, 8).map((resource, index) => ({
          ...resource.location,
          label: `${resource.kind} ${index + 1}`,
          note: 'This element does not declare loading="lazy".',
        })),
      },
    }),
  );

  const compressibleProbes = [primaryAttempt, ...artifacts.resourceProbes.filter((probe) =>
    /(text\/|javascript|json|css|svg|xml)/i.test(probe.contentType ?? ""),
  )];
  const compressedCount = compressibleProbes.filter(
    (probe) => Boolean(probe.headers["content-encoding"]),
  ).length;
  const compressionRatio = compressibleProbes.length
    ? compressedCount / compressibleProbes.length
    : 1;
  const compressionStatus =
    compressionRatio >= 0.8
      ? { status: "pass" as const, severity: "info" as const }
      : compressionRatio >= 0.4
        ? { status: "warning" as const, severity: "low" as const }
        : { status: "fail" as const, severity: "medium" as const };
  findings.push(
    buildPerformanceCheck({
      checkKey: "compression-enabled",
      title: "Compression enabled",
      ...compressionStatus,
      shortDescription: `${compressedCount} of ${compressibleProbes.length} sampled text responses advertise compression.`,
      whyItMatters:
        "Compression reduces transfer size for HTML, CSS, JavaScript, SVG, and other text responses.",
      recommendation:
        compressionStatus.status === "pass"
          ? "Keep Brotli or gzip enabled for text responses."
          : "Enable Brotli or gzip for HTML, CSS, JavaScript, and other text assets.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: 'response.headers["content-encoding"] on HTML and text assets',
        summary: "Calculated from the main document and sampled text asset responses.",
        compressedResponses: compressedCount,
        sampledResponses: compressibleProbes.length,
      },
    }),
  );

  const cacheableAssets = artifacts.resourceProbes.filter((probe) =>
    /(javascript|css|image|font)/i.test(probe.contentType ?? ""),
  );
  const cachedAssets = countHeaderCaching(cacheableAssets);
  const cacheStatus =
    cacheableAssets.length === 0 || cachedAssets / Math.max(cacheableAssets.length, 1) >= 0.75
      ? { status: "pass" as const, severity: "info" as const }
      : cachedAssets / Math.max(cacheableAssets.length, 1) >= 0.4
        ? { status: "warning" as const, severity: "low" as const }
        : { status: "fail" as const, severity: "medium" as const };
  findings.push(
    buildPerformanceCheck({
      checkKey: "cache-headers",
      title: "Cache headers",
      ...cacheStatus,
      shortDescription: `${cachedAssets} of ${cacheableAssets.length} sampled static assets expose cache hints.`,
      whyItMatters:
        "Strong cache headers reduce repeat transfer cost and improve responsiveness on subsequent visits.",
      recommendation:
        cacheStatus.status === "pass"
          ? "Keep static asset caching long-lived and versioned."
          : "Use `Cache-Control`, `ETag`, or `Last-Modified` consistently on important static assets.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: "Static asset cache-control, ETag, or Last-Modified headers",
        summary: "Calculated from sampled script, stylesheet, image, and font responses.",
        cachedAssets,
        sampledAssets: cacheableAssets.length,
      },
    }),
  );

  const renderBlockingStatus =
    renderBlockingScripts.length === 0 && stylesheets.length <= 3
      ? { status: "pass" as const, severity: "info" as const }
      : renderBlockingScripts.length <= 1 && stylesheets.length <= 5
        ? { status: "warning" as const, severity: "low" as const }
        : { status: "fail" as const, severity: "medium" as const };
  findings.push(
    buildPerformanceCheck({
      checkKey: "render-blocking-resources",
      title: "Render-blocking resources",
      ...renderBlockingStatus,
      shortDescription: `${renderBlockingScripts.length} head scripts and ${stylesheets.length} stylesheets were found in the initial HTML.`,
      whyItMatters:
        "Render-blocking CSS and synchronous head scripts delay first paint and interaction readiness.",
      recommendation:
        renderBlockingStatus.status === "pass"
          ? "Keep the critical path light."
          : "Defer non-critical scripts and minimize the number of blocking stylesheets in the head.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: "Head scripts and stylesheets from the initial HTML",
        summary: "This check counted scripts found in the head and linked stylesheets in the primary page markup.",
        renderBlockingScripts: renderBlockingScripts.length,
        stylesheets: stylesheets.length,
        locations: [...renderBlockingScripts, ...stylesheets].slice(0, 8).map((resource, index) => ({
          ...resource.location,
          label: `${resource.kind} ${index + 1}`,
        })),
      },
    }),
  );

  const thirdPartyScriptBytes = sumKnownBytes(externalScriptEntries.map((entry) => entry.probe));
  const thirdPartyStatus = lowerBetterStatus(
    thirdPartyScriptBytes,
    120_000,
    350_000,
    "info",
    "low",
    "medium",
  );
  findings.push(
    buildPerformanceCheck({
      checkKey: "third-party-script-weight",
      title: "Third-party script weight",
      ...thirdPartyStatus,
      shortDescription: `${externalScriptEntries.length} third-party scripts account for ${formatBytes(thirdPartyScriptBytes)} of sampled JavaScript weight.`,
      whyItMatters:
        "Third-party JavaScript adds network, parse, and reliability cost that is outside your direct deployment control.",
      recommendation:
        thirdPartyStatus.status === "pass"
          ? "Keep third-party JavaScript limited to what the page truly needs."
          : "Audit and defer or remove third-party scripts that do not justify their cost.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: "Third-party script[src] requests from the initial HTML",
        summary: "Calculated from sampled third-party script assets discovered in the primary page markup.",
        thirdPartyScriptCount: externalScriptEntries.length,
        thirdPartyScriptBytes,
      },
      premiumOnly: true,
    }),
  );

  const redirectStatus = lowerBetterStatus(
    primaryAttempt.redirectChain.length,
    1,
    2,
    "info",
    "low",
    "medium",
  );
  findings.push(
    buildPerformanceCheck({
      checkKey: "redirect-chains",
      title: "Redirect chains",
      ...redirectStatus,
      shortDescription: `The primary navigation required ${primaryAttempt.redirectChain.length} redirect hops.`,
      whyItMatters:
        "Each extra redirect adds latency before the final page and assets can begin loading.",
      recommendation:
        redirectStatus.status === "pass"
          ? "Keep redirect chains short and direct."
          : "Reduce redirect hops so users reach the final URL in as few steps as possible.",
      evidence: {
        checkedUrl: target.originalInput,
        expectedLocation: "Redirect chain from the scanned URL to the final page",
        summary: "Calculated from the redirects followed before the final HTML response.",
        redirectChain: primaryAttempt.redirectChain,
      },
    }),
  );

  const fontBytes = sumKnownBytes(fonts);
  const fontStatus = lowerBetterStatus(fontBytes, 150_000, 300_000, "info", "low", "medium");
  findings.push(
    buildPerformanceCheck({
      checkKey: "fonts-optimization",
      title: "Fonts optimization",
      ...fontStatus,
      shortDescription: `${fonts.length} sampled font assets account for ${formatBytes(fontBytes)}.`,
      whyItMatters:
        "Too many or too-heavy fonts increase render delay and can cause text shifts during page load.",
      recommendation:
        fontStatus.status === "pass"
          ? "Keep font payloads small and only load the weights you use."
          : "Reduce font families, weights, and bytes, and preload only the most important fonts.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: "Sampled font requests and font preloads",
        summary: "Calculated from sampled font responses discovered in the primary page markup.",
        fontCount: fonts.length,
        fontBytes,
      },
    }),
  );

  const domStatus = lowerBetterStatus(primaryPage.nodeCount, 1_500, 3_000, "info", "low", "medium");
  findings.push(
    buildPerformanceCheck({
      checkKey: "dom-size",
      title: "DOM size",
      ...domStatus,
      shortDescription: `The primary page contains ${primaryPage.nodeCount} DOM nodes in the fetched HTML.`,
      whyItMatters:
        "Large DOMs increase style, layout, and scripting cost and can pressure low-powered devices.",
      recommendation:
        domStatus.status === "pass"
          ? "Keep the DOM size controlled as the page grows."
          : "Trim excessive markup, repeated wrappers, and deferred content in the initial HTML.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: "Node count of the fetched primary HTML document",
        summary: "Counted from the server-rendered HTML before any client-side rendering work.",
        nodeCount: primaryPage.nodeCount,
      },
    }),
  );

  const mainThreadPressureScore =
    (totalJsBytes >= 700_000 ? 2 : totalJsBytes >= 300_000 ? 1 : 0) +
    (renderBlockingScripts.length >= 2 ? 2 : renderBlockingScripts.length === 1 ? 1 : 0) +
    (primaryPage.nodeCount >= 3_000 ? 2 : primaryPage.nodeCount >= 1_500 ? 1 : 0);
  const mainThreadStatus =
    mainThreadPressureScore >= 4
      ? { status: "fail" as const, severity: "medium" as const }
      : mainThreadPressureScore >= 2
        ? { status: "warning" as const, severity: "low" as const }
        : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildPerformanceCheck({
      checkKey: "long-tasks-main-thread-pressure",
      title: "Main thread pressure hint",
      ...mainThreadStatus,
      shortDescription:
        mainThreadStatus.status === "pass"
          ? "The sampled JavaScript, DOM size, and blocking patterns suggest manageable main-thread pressure."
          : "The sampled JavaScript, DOM size, and blocking patterns suggest elevated main-thread pressure.",
      whyItMatters:
        "Heavy main-thread work can delay input responsiveness and make pages feel sluggish even after network requests finish.",
      recommendation:
        mainThreadStatus.status === "pass"
          ? "Keep JavaScript and critical-path work under control."
          : "Reduce JavaScript bytes, synchronous work, and excessive DOM complexity on the first view.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: "Heuristic based on sampled JavaScript size, head scripts, and DOM size",
        summary: "This is a heuristic hint, not a browser PerformanceObserver measurement.",
        totalJsBytes,
        renderBlockingScripts: renderBlockingScripts.length,
        nodeCount: primaryPage.nodeCount,
      },
    }),
  );

  const largestImage = imageProbes.sort(
    (left, right) => (right.probe.contentLength ?? 0) - (left.probe.contentLength ?? 0),
  )[0];
  const lcpRiskScore =
    (primaryAttempt.durationMs >= 1_500 ? 1 : 0) +
    (renderBlockingScripts.length > 0 || stylesheets.length > 5 ? 1 : 0) +
    (largestImage && (largestImage.probe.contentLength ?? 0) >= 500_000 ? 1 : 0);
  const lcpStatus =
    lcpRiskScore >= 3
      ? { status: "fail" as const, severity: "medium" as const }
      : lcpRiskScore >= 1
        ? { status: "warning" as const, severity: "low" as const }
        : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildPerformanceCheck({
      checkKey: "lcp-style-hint",
      title: "LCP-style hint",
      ...lcpStatus,
      shortDescription:
        lcpStatus.status === "pass"
          ? "The sampled document and hero asset characteristics do not suggest a strong LCP risk."
          : "The sampled document and hero asset characteristics suggest an elevated LCP risk.",
      whyItMatters:
        "The largest visible content often determines how quickly users feel the page is usable.",
      recommendation:
        lcpStatus.status === "pass"
          ? "Keep the main content fast and lightweight."
          : "Reduce TTFB, render-blocking work, and oversized hero assets on the first view.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: "Heuristic based on TTFB, blocking assets, and the largest sampled image",
        summary: "This is a heuristic hint, not a Lighthouse or browser LCP metric.",
        ttfbMs: primaryAttempt.durationMs,
        renderBlockingScripts: renderBlockingScripts.length,
        largestImageBytes: largestImage?.probe.contentLength ?? null,
      },
    }),
  );

  const layoutShiftCandidates = [...images, ...iframes].filter(
    (resource) => !resource.declaredWidth || !resource.declaredHeight,
  );
  const clsStatus =
    layoutShiftCandidates.length === 0
      ? { status: "pass" as const, severity: "info" as const }
      : layoutShiftCandidates.length > 5
        ? { status: "fail" as const, severity: "medium" as const }
        : { status: "warning" as const, severity: "low" as const };
  findings.push(
    buildPerformanceCheck({
      checkKey: "cls-style-hint",
      title: "CLS-style hint",
      ...clsStatus,
      shortDescription:
        layoutShiftCandidates.length === 0
          ? "Sampled images and iframes expose width and height attributes."
          : `${layoutShiftCandidates.length} sampled images or iframes are missing width and/or height attributes.`,
      whyItMatters:
        "Missing intrinsic dimensions can contribute to layout shifts during page load.",
      recommendation:
        layoutShiftCandidates.length === 0
          ? "Keep reserving layout space for media and embeds."
          : "Add width and height attributes or otherwise reserve stable space for media and embeds.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: "img and iframe elements should reserve layout space",
        summary: "This is a heuristic layout-shift hint based on sampled media attributes.",
        layoutShiftCandidates: layoutShiftCandidates.length,
        locations: layoutShiftCandidates.slice(0, 8).map((resource, index) => ({
          ...resource.location,
          label: `${resource.kind} ${index + 1}`,
          note: "Missing width and/or height attributes.",
        })),
      },
    }),
  );

  const gated = applyPremiumGating(findings, 10);
  return {
    score: computeScore(findings),
    findings: gated,
  };
}
