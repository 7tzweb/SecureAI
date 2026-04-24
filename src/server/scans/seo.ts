import { type FindingEvidenceLocation, type FindingStatus, type Severity } from "@/lib/types";
import { applyPremiumGating, computeScore } from "@/lib/utils";
import {
  type LinkProbe,
  type PageSnapshot,
  isSuccessfulStatus,
  loadAuditArtifacts,
} from "@/server/scans/artifacts";
import {
  createFinding,
  createResponseLocation,
  getOrigin,
  loadAttempt,
} from "@/server/scans/helpers";
import { type CategoryScanResult, type NormalizedTarget } from "@/server/scans/types";

function buildSeoCheck(input: {
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
    category: "seo",
  });
}

function pageEvidence(page: PageSnapshot, expectedLocation: string, summary?: string) {
  return {
    checkedUrl: page.url,
    expectedLocation,
    ...(summary ? { summary } : {}),
  };
}

function brokenLinkLocations(probes: LinkProbe[]) {
  return probes.slice(0, 8).map((probe) => ({
    ...probe.location,
    note: `Found on ${probe.sourceUrl} and returned status ${probe.status ?? "request failed"}.`,
  }));
}

function findDuplicateValues(
  pages: PageSnapshot[],
  selector: (page: PageSnapshot) => string,
  label: string,
) {
  const groups = new Map<string, PageSnapshot[]>();

  pages.forEach((page) => {
    const value = selector(page).trim();
    if (!value) {
      return;
    }

    const existing = groups.get(value) ?? [];
    existing.push(page);
    groups.set(value, existing);
  });

  return [...groups.entries()]
    .filter(([, group]) => group.length > 1)
    .flatMap(([value, group]) =>
      group.map((page, index) =>
        createResponseLocation({
          label: `${label} duplicate ${index + 1}`,
          url: page.url,
          path: label === "Title" ? "head > title" : 'head > meta[name="description"]',
          value,
          note: `The same ${label.toLowerCase()} appears on ${group.length} crawled pages.`,
        }),
      ),
    );
}

function evaluateHeadingStructure(page: PageSnapshot) {
  if (page.headings.length <= 1) {
    return {
      status: "pass" as const,
      severity: "info" as const,
      summary: "The page has a simple heading outline with no structural jumps.",
      locations: page.headings.slice(0, 3).map((heading) => heading.location),
    };
  }

  const jumps: FindingEvidenceLocation[] = [];
  for (let index = 1; index < page.headings.length; index += 1) {
    const previous = page.headings[index - 1];
    const current = page.headings[index];
    if (current.level - previous.level > 1) {
      jumps.push({
        ...current.location,
        note: `Heading level jumps from H${previous.level} to H${current.level}.`,
      });
    }
  }

  if (jumps.length > 0) {
    return {
      status: "warning" as const,
      severity: "low" as const,
      summary: `Detected ${jumps.length} heading level jumps in the primary page outline.`,
      locations: jumps.slice(0, 6),
    };
  }

  return {
    status: "pass" as const,
    severity: "info" as const,
    summary: "The H1-H6 order looks consistent on the primary page.",
    locations: page.headings.slice(0, 4).map((heading) => heading.location),
  };
}

export async function runSeoScan(target: NormalizedTarget): Promise<CategoryScanResult> {
  const artifacts = await loadAuditArtifacts(target);
  const primaryPage = artifacts.primaryPage;
  const primaryAttempt = artifacts.context.primary;

  if (!primaryPage || !primaryAttempt) {
    throw new Error("Unable to fetch and parse the target website.");
  }

  const findings = [];
  const crawledPages = [primaryPage, ...artifacts.crawledPages];
  const origin = getOrigin(primaryPage.url);

  findings.push(
    buildSeoCheck({
      checkKey: "title-tag-exists",
      title: "Title tag exists",
      status: primaryPage.title ? "pass" : "fail",
      severity: primaryPage.title ? "info" : "high",
      shortDescription: primaryPage.title
        ? "The primary page includes a title tag."
        : "The primary page is missing a title tag.",
      whyItMatters:
        "The title tag strongly influences search snippets, relevance signals, and tab/bookmark usability.",
      recommendation: primaryPage.title
        ? "Keep the title unique and aligned with the page intent."
        : "Add a concise, descriptive title tag to the document head.",
      evidence: primaryPage.title
        ? {
            ...pageEvidence(primaryPage, "head > title", "The document title was extracted successfully."),
            title: primaryPage.title,
            locations: [
              createResponseLocation({
                label: "Document title",
                url: primaryPage.url,
                path: "head > title",
                value: primaryPage.title,
              }),
            ],
          }
        : pageEvidence(primaryPage, "head > title", "No title element was found in the document head."),
    }),
  );

  const titleLengthStatus = !primaryPage.title
    ? { status: "info" as const, severity: "info" as const }
    : primaryPage.titleLength >= 20 && primaryPage.titleLength <= 65
      ? { status: "pass" as const, severity: "info" as const }
      : { status: "warning" as const, severity: "low" as const };
  findings.push(
    buildSeoCheck({
      checkKey: "title-length",
      title: "Title length",
      ...titleLengthStatus,
      shortDescription: !primaryPage.title
        ? "Title length could not be evaluated because the title tag is missing."
        : `The title is ${primaryPage.titleLength} characters long.`,
      whyItMatters:
        "Very short or very long titles can reduce relevance and snippet clarity in search results.",
      recommendation: !primaryPage.title
        ? "Add a title tag before evaluating title length."
        : "Aim for a title that is usually between 20 and 65 characters.",
      evidence: {
        ...pageEvidence(primaryPage, "head > title", `Measured ${primaryPage.titleLength} title characters.`),
        length: primaryPage.titleLength,
        title: primaryPage.title,
      },
    }),
  );

  findings.push(
    buildSeoCheck({
      checkKey: "meta-description-exists",
      title: "Meta description exists",
      status: primaryPage.description ? "pass" : "warning",
      severity: primaryPage.description ? "info" : "low",
      shortDescription: primaryPage.description
        ? "The primary page defines a meta description."
        : "The primary page is missing a meta description.",
      whyItMatters:
        "Search engines often use the meta description as the starting point for the visible snippet.",
      recommendation: primaryPage.description
        ? "Keep the description aligned with the page content and search intent."
        : "Add a clear meta description that explains the page purpose.",
      evidence: primaryPage.description
        ? {
            ...pageEvidence(
              primaryPage,
              'head > meta[name="description"]',
              "A description meta tag was found in the document head.",
            ),
            description: primaryPage.description,
            locations: [
              createResponseLocation({
                label: "Meta description",
                url: primaryPage.url,
                path: 'head > meta[name="description"]',
                value: primaryPage.description,
              }),
            ],
          }
        : pageEvidence(
            primaryPage,
            'head > meta[name="description"]',
            "No description meta tag was found in the document head.",
          ),
    }),
  );

  const descriptionLengthStatus = !primaryPage.description
    ? { status: "info" as const, severity: "info" as const }
    : primaryPage.descriptionLength >= 70 && primaryPage.descriptionLength <= 160
      ? { status: "pass" as const, severity: "info" as const }
      : { status: "warning" as const, severity: "low" as const };
  findings.push(
    buildSeoCheck({
      checkKey: "meta-description-length",
      title: "Meta description length",
      ...descriptionLengthStatus,
      shortDescription: !primaryPage.description
        ? "Description length could not be evaluated because the tag is missing."
        : `The description is ${primaryPage.descriptionLength} characters long.`,
      whyItMatters:
        "Descriptions that are too short or too long can lower search snippet quality and click-through behavior.",
      recommendation: !primaryPage.description
        ? "Add a meta description before evaluating its length."
        : "Keep the meta description in a practical range of roughly 70 to 160 characters.",
      evidence: {
        ...pageEvidence(
          primaryPage,
          'head > meta[name="description"]',
          `Measured ${primaryPage.descriptionLength} description characters.`,
        ),
        length: primaryPage.descriptionLength,
        description: primaryPage.description,
      },
    }),
  );

  findings.push(
    buildSeoCheck({
      checkKey: "canonical-exists",
      title: "Canonical tag exists",
      status: primaryPage.canonical ? "pass" : "warning",
      severity: primaryPage.canonical ? "info" : "low",
      shortDescription: primaryPage.canonical
        ? "The primary page publishes a canonical URL."
        : "The primary page does not publish a canonical tag.",
      whyItMatters:
        "Canonical tags help search engines consolidate duplicate or near-duplicate URLs to a preferred version.",
      recommendation: primaryPage.canonical
        ? "Keep the canonical URL stable and aligned with the public preferred page."
        : "Add a canonical URL that points to the preferred indexable version of the page.",
      evidence: primaryPage.canonical
        ? {
            ...pageEvidence(
              primaryPage,
              'head > link[rel="canonical"]',
              "A canonical tag was found in the document head.",
            ),
            canonical: primaryPage.canonical,
            locations: [
              createResponseLocation({
                label: "Canonical tag",
                url: primaryPage.url,
                path: 'head > link[rel="canonical"]',
                value: primaryPage.canonical,
              }),
            ],
          }
        : pageEvidence(
            primaryPage,
            'head > link[rel="canonical"]',
            "No canonical tag was found in the document head.",
          ),
    }),
  );

  let canonicalStatus: FindingStatus = "warning";
  let canonicalSeverity: Severity = "low";
  let canonicalSummary = "Canonical validity was not evaluated because the primary page does not publish a canonical tag.";
  let canonicalEvidence: Record<string, unknown> = pageEvidence(
    primaryPage,
    'head > link[rel="canonical"]',
    canonicalSummary,
  );
  if (primaryPage.canonical) {
    try {
      const canonicalUrl = new URL(primaryPage.canonical, primaryPage.url).toString();
      const canonicalAttempt = await loadAttempt(canonicalUrl, { includeBody: false, timeoutMs: 8_000 });
      if (!canonicalAttempt || canonicalAttempt.status >= 400) {
        canonicalStatus = "fail";
        canonicalSeverity = "medium";
        canonicalSummary = "The canonical tag resolves to a URL that did not return a successful response.";
      } else if (new URL(canonicalUrl).hostname !== target.targetHostname) {
        canonicalStatus = "warning";
        canonicalSeverity = "low";
        canonicalSummary = "The canonical URL points to a different hostname than the scanned target.";
      } else {
        canonicalStatus = "pass";
        canonicalSeverity = "info";
        canonicalSummary = "The canonical URL is syntactically valid and returned a successful response.";
      }
      canonicalEvidence = {
        ...pageEvidence(
          primaryPage,
          'head > link[rel="canonical"]',
          canonicalSummary,
        ),
        canonicalUrl,
        canonicalStatusCode: canonicalAttempt?.status ?? null,
        locations: [
          createResponseLocation({
            label: "Canonical URL",
            url: primaryPage.url,
            path: 'head > link[rel="canonical"]',
            value: canonicalUrl,
          }),
        ],
      };
    } catch {
      canonicalStatus = "fail";
      canonicalSeverity = "medium";
      canonicalSummary = "The canonical tag could not be resolved into a valid absolute URL.";
      canonicalEvidence = pageEvidence(
        primaryPage,
        'head > link[rel="canonical"]',
        canonicalSummary,
      );
    }
  } else {
    canonicalStatus = "info";
    canonicalSeverity = "info";
  }
  findings.push(
    buildSeoCheck({
      checkKey: "canonical-validity",
      title: "Canonical validity",
      status: canonicalStatus,
      severity: canonicalSeverity,
      shortDescription: canonicalSummary,
      whyItMatters:
        "A broken or misleading canonical tag can send crawlers to the wrong URL and weaken index consolidation.",
      recommendation: primaryPage.canonical
        ? "Point the canonical tag to a valid, preferred public URL that returns successfully."
        : "Add a canonical tag before validating its target.",
      evidence: canonicalEvidence,
    }),
  );

  const robotsAttempt = await loadAttempt(`${origin}/robots.txt`, {
    timeoutMs: 8_000,
  });
  findings.push(
    buildSeoCheck({
      checkKey: "robots-txt-exists",
      title: "robots.txt exists",
      status: robotsAttempt && robotsAttempt.status < 400 ? "pass" : "warning",
      severity: robotsAttempt && robotsAttempt.status < 400 ? "info" : "low",
      shortDescription:
        robotsAttempt && robotsAttempt.status < 400
          ? "robots.txt is reachable on the site root."
          : "robots.txt was not found on the site root.",
      whyItMatters:
        "robots.txt helps search crawlers understand the intended crawl policy and can advertise sitemap locations.",
      recommendation:
        robotsAttempt && robotsAttempt.status < 400
          ? "Keep robots.txt aligned with the crawl policy you want production bots to follow."
          : "Publish a robots.txt file at the site root.",
      evidence: {
        checkedUrl: `${origin}/robots.txt`,
        expectedLocation: "/robots.txt",
        summary:
          robotsAttempt && robotsAttempt.status < 400
            ? "robots.txt returned a successful response."
            : "robots.txt did not return a successful response.",
        statusCode: robotsAttempt?.status ?? null,
      },
    }),
  );

  const sitemapCandidates = new Set<string>([`${origin}/sitemap.xml`]);
  if (robotsAttempt?.bodyText) {
    robotsAttempt.bodyText
      .split(/\r?\n/)
      .map((line) => line.match(/^sitemap:\s*(.+)$/i)?.[1]?.trim())
      .filter((line): line is string => Boolean(line))
      .forEach((line) => {
        try {
          sitemapCandidates.add(new URL(line, origin).toString());
        } catch {
          sitemapCandidates.add(line);
        }
      });
  }
  const sitemapAttempts = await Promise.all(
    [...sitemapCandidates].slice(0, 4).map((url) => loadAttempt(url, { includeBody: false, timeoutMs: 8_000 })),
  );
  const workingSitemap = sitemapAttempts.find((attempt) => attempt && attempt.status < 400) ?? null;
  findings.push(
    buildSeoCheck({
      checkKey: "sitemap-exists",
      title: "Sitemap exists",
      status: workingSitemap ? "pass" : "warning",
      severity: workingSitemap ? "info" : "low",
      shortDescription: workingSitemap
        ? "A sitemap endpoint returned a successful response."
        : "No sitemap endpoint returned a successful response.",
      whyItMatters:
        "XML sitemaps help crawlers discover and prioritize URLs, especially on larger or frequently updated sites.",
      recommendation: workingSitemap
        ? "Keep the sitemap current and reference it from robots.txt."
        : "Publish a sitemap.xml or advertise sitemap URLs from robots.txt.",
      evidence: {
        checkedUrl: [...sitemapCandidates].slice(0, 4).join(", "),
        expectedLocation: "/sitemap.xml or Sitemap: entries in robots.txt",
        summary: workingSitemap
          ? `Found a working sitemap at ${workingSitemap.finalUrl}.`
          : "No tested sitemap candidate returned a successful response.",
        locations: workingSitemap
          ? [
              createResponseLocation({
                label: "Working sitemap",
                url: workingSitemap.finalUrl,
                path: new URL(workingSitemap.finalUrl).pathname,
              }),
            ]
          : undefined,
      },
    }),
  );

  const metaRobotsStatus =
    primaryPage.robots.toLowerCase().includes("noindex") || primaryPage.robots.toLowerCase().includes("nofollow")
      ? { status: "warning" as const, severity: "medium" as const }
      : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSeoCheck({
      checkKey: "meta-robots",
      title: "Meta robots policy",
      ...metaRobotsStatus,
      shortDescription: primaryPage.robots
        ? `The page declares robots="${primaryPage.robots}".`
        : "No meta robots tag was found, so the default crawl policy applies.",
      whyItMatters:
        "Unexpected noindex or nofollow directives can remove pages from search or limit link discovery.",
      recommendation: primaryPage.robots
        ? "Verify that the robots policy matches the page's intended search visibility."
        : "Add a meta robots tag only when you need a page-specific indexing policy.",
      evidence: primaryPage.robots
        ? {
            ...pageEvidence(primaryPage, 'head > meta[name="robots"]', "Robots policy was read from the document head."),
            robotsMeta: primaryPage.robots,
            locations: [
              createResponseLocation({
                label: "Robots meta",
                url: primaryPage.url,
                path: 'head > meta[name="robots"]',
                value: primaryPage.robots,
              }),
            ],
          }
        : pageEvidence(
            primaryPage,
            'head > meta[name="robots"]',
            "No meta robots tag was found on the primary page.",
          ),
    }),
  );

  const h1Status =
    primaryPage.h1Count === 1
      ? { status: "pass" as const, severity: "info" as const }
      : { status: "warning" as const, severity: "low" as const };
  findings.push(
    buildSeoCheck({
      checkKey: "h1-exists",
      title: "H1 presence",
      ...h1Status,
      shortDescription:
        primaryPage.h1Count === 1
          ? "The page contains exactly one H1 heading."
          : `The page contains ${primaryPage.h1Count} H1 headings.`,
      whyItMatters:
        "A clear primary heading helps crawlers and users quickly understand the page topic.",
      recommendation:
        primaryPage.h1Count === 1
          ? "Keep the H1 aligned with the page subject."
          : "Use one descriptive H1 and structure supporting content with H2-H6 headings.",
      evidence: {
        ...pageEvidence(primaryPage, "body h1", `Detected ${primaryPage.h1Count} H1 headings.`),
        h1Count: primaryPage.h1Count,
        locations: primaryPage.headings
          .filter((heading) => heading.level === 1)
          .slice(0, 6)
          .map((heading) => heading.location),
      },
    }),
  );

  const headingStructure = evaluateHeadingStructure(primaryPage);
  findings.push(
    buildSeoCheck({
      checkKey: "heading-structure",
      title: "Heading structure",
      status: headingStructure.status,
      severity: headingStructure.severity,
      shortDescription: headingStructure.summary,
      whyItMatters:
        "Heading hierarchy helps search engines and assistive technologies understand the structure of the page.",
      recommendation:
        headingStructure.status === "pass"
          ? "Keep using a logical H1-H6 outline as the page evolves."
          : "Avoid skipping heading levels when introducing new sections.",
      evidence: {
        ...pageEvidence(primaryPage, "body h1-h6", headingStructure.summary),
        locations: headingStructure.locations,
      },
    }),
  );

  const allImages = crawledPages.flatMap((page) => page.images);
  const missingAltImages = allImages.filter((image) => !image.alt);
  const altCoverage = allImages.length ? Math.round(((allImages.length - missingAltImages.length) / allImages.length) * 100) : 100;
  const altStatus =
    allImages.length === 0 || altCoverage >= 90
      ? { status: "pass" as const, severity: "info" as const }
      : altCoverage >= 60
        ? { status: "warning" as const, severity: "low" as const }
        : { status: "fail" as const, severity: "medium" as const };
  findings.push(
    buildSeoCheck({
      checkKey: "image-alt-text",
      title: "Image alt text",
      ...altStatus,
      shortDescription: `${missingAltImages.length} of ${allImages.length} sampled images are missing alt text.`,
      whyItMatters:
        "Alt text improves accessibility and helps search engines understand the meaning of non-decorative images.",
      recommendation:
        altStatus.status === "pass"
          ? "Keep alt text meaningful and use empty alt values only for purely decorative images."
          : "Add meaningful alt text to informative images and use empty alt values for decorative assets.",
      evidence: {
        ...pageEvidence(
          primaryPage,
          "img[alt] or img[alt=\"\"] for decorative assets",
          `Alt coverage across ${crawledPages.length} crawled pages is ${altCoverage}%.`,
        ),
        totalImages: allImages.length,
        missingAlt: missingAltImages.length,
        coveragePercent: altCoverage,
        locations: missingAltImages.slice(0, 8).map((image, index) => ({
          ...image.location,
          label: `Image ${index + 1}`,
          note: "This image is missing an alt attribute.",
        })),
      },
    }),
  );

  const requiredOgTags = ["og:title", "og:description", "og:image"];
  const ogMatches = requiredOgTags.filter((tag) => primaryPage.openGraphTags.includes(tag));
  const ogStatus =
    ogMatches.length === requiredOgTags.length
      ? { status: "pass" as const, severity: "info" as const }
      : { status: "warning" as const, severity: "low" as const };
  findings.push(
    buildSeoCheck({
      checkKey: "open-graph-tags",
      title: "Open Graph tags",
      ...ogStatus,
      shortDescription: `Found ${ogMatches.length} of ${requiredOgTags.length} core Open Graph tags.`,
      whyItMatters:
        "Open Graph metadata improves how URLs render in messaging apps and social previews.",
      recommendation:
        ogStatus.status === "pass"
          ? "Keep `og:title`, `og:description`, and `og:image` aligned with the current content."
          : "Add the core Open Graph tags: `og:title`, `og:description`, and `og:image`.",
      evidence: {
        ...pageEvidence(primaryPage, 'head > meta[property^="og:"]', "Collected Open Graph tags from the primary page."),
        detectedOgTags: primaryPage.openGraphTags,
      },
    }),
  );

  const requiredTwitterTags = ["twitter:card", "twitter:title", "twitter:description"];
  const twitterMatches = requiredTwitterTags.filter((tag) => primaryPage.twitterTags.includes(tag));
  const twitterStatus =
    twitterMatches.length === requiredTwitterTags.length
      ? { status: "pass" as const, severity: "info" as const }
      : { status: "warning" as const, severity: "low" as const };
  findings.push(
    buildSeoCheck({
      checkKey: "twitter-card-tags",
      title: "Twitter card tags",
      ...twitterStatus,
      shortDescription: `Found ${twitterMatches.length} of ${requiredTwitterTags.length} core Twitter card tags.`,
      whyItMatters:
        "Twitter card metadata still influences how many platforms preview shared pages.",
      recommendation:
        twitterStatus.status === "pass"
          ? "Keep the Twitter metadata consistent with the Open Graph values."
          : "Add at least `twitter:card`, `twitter:title`, and `twitter:description`.",
      evidence: {
        ...pageEvidence(primaryPage, 'head > meta[name^="twitter:"]', "Collected Twitter card tags from the primary page."),
        detectedTwitterTags: primaryPage.twitterTags,
      },
    }),
  );

  findings.push(
    buildSeoCheck({
      checkKey: "structured-data-presence",
      title: "Structured data presence",
      status: primaryPage.structuredDataCount > 0 ? "pass" : "info",
      severity: "info",
      shortDescription:
        primaryPage.structuredDataCount > 0
          ? `Detected ${primaryPage.structuredDataCount} JSON-LD blocks on the primary page.`
          : "No JSON-LD structured data was detected on the primary page.",
      whyItMatters:
        "Structured data can help search engines interpret the page entity and unlock richer search features.",
      recommendation:
        primaryPage.structuredDataCount > 0
          ? "Keep the structured data accurate and aligned with the visible page content."
          : "Add schema.org JSON-LD if it accurately represents the page content.",
      evidence: {
        ...pageEvidence(
          primaryPage,
          'script[type="application/ld+json"]',
          `Detected ${primaryPage.structuredDataCount} structured data blocks.`,
        ),
        structuredDataCount: primaryPage.structuredDataCount,
      },
      premiumOnly: true,
    }),
  );

  const viewportStatus = !primaryPage.viewport
    ? { status: "warning" as const, severity: "low" as const }
    : /width=device-width/i.test(primaryPage.viewport)
      ? { status: "pass" as const, severity: "info" as const }
      : { status: "warning" as const, severity: "low" as const };
  findings.push(
    buildSeoCheck({
      checkKey: "viewport-meta",
      title: "Viewport meta",
      ...viewportStatus,
      shortDescription: primaryPage.viewport
        ? `Viewport is set to "${primaryPage.viewport}".`
        : "The page is missing a viewport meta tag.",
      whyItMatters:
        "Mobile-friendly rendering depends on a correct viewport declaration in the document head.",
      recommendation: primaryPage.viewport
        ? "Keep the viewport aligned with responsive behavior, usually `width=device-width, initial-scale=1`."
        : 'Add `<meta name="viewport" content="width=device-width, initial-scale=1" />`.',
      evidence: primaryPage.viewport
        ? {
            ...pageEvidence(primaryPage, 'head > meta[name="viewport"]', "Viewport metadata was found on the primary page."),
            viewport: primaryPage.viewport,
          }
        : pageEvidence(primaryPage, 'head > meta[name="viewport"]', "No viewport tag was found in the document head."),
    }),
  );

  findings.push(
    buildSeoCheck({
      checkKey: "html-lang-attribute",
      title: "HTML lang attribute",
      status: primaryPage.lang ? "pass" : "warning",
      severity: primaryPage.lang ? "info" : "low",
      shortDescription: primaryPage.lang
        ? `The HTML element declares lang="${primaryPage.lang}".`
        : "The HTML element does not declare a lang attribute.",
      whyItMatters:
        "Language metadata helps search engines and assistive technologies interpret the page correctly.",
      recommendation: primaryPage.lang
        ? "Keep the language code aligned with the actual page language."
        : "Add a `lang` attribute on the `<html>` element.",
      evidence: primaryPage.lang
        ? {
            ...pageEvidence(primaryPage, "html[lang]", "The root HTML element exposes a language code."),
            lang: primaryPage.lang,
            locations: [
              createResponseLocation({
                label: "HTML root element",
                url: primaryPage.url,
                path: "html[lang]",
                value: primaryPage.lang,
              }),
            ],
          }
        : pageEvidence(primaryPage, "html[lang]", "No `lang` attribute was found on the root HTML element."),
    }),
  );

  const brokenInternalLinks = artifacts.internalLinkProbes.filter(
    (probe) => !isSuccessfulStatus(probe.status),
  );
  const internalBrokenStatus =
    brokenInternalLinks.length === 0
      ? { status: "pass" as const, severity: "info" as const }
      : brokenInternalLinks.length <= 2
        ? { status: "warning" as const, severity: "low" as const }
        : { status: "fail" as const, severity: "medium" as const };
  findings.push(
    buildSeoCheck({
      checkKey: "broken-internal-links",
      title: "Broken internal links",
      ...internalBrokenStatus,
      shortDescription:
        brokenInternalLinks.length === 0
          ? `No broken internal links were detected across ${artifacts.internalLinkProbes.length} sampled internal pages.`
          : `${brokenInternalLinks.length} of ${artifacts.internalLinkProbes.length} sampled internal links returned errors.`,
      whyItMatters:
        "Broken internal links waste crawl budget, create dead ends, and degrade user trust.",
      recommendation:
        brokenInternalLinks.length === 0
          ? "Keep monitoring internal links as new pages are published."
          : "Fix or remove internal links that return 4xx/5xx responses.",
      evidence: {
        ...pageEvidence(
          primaryPage,
          "Internal links discovered during the limited crawl",
          brokenInternalLinks.length === 0
            ? "All sampled internal links returned successful or redirected responses."
            : "Some sampled internal links returned errors.",
        ),
        sampledLinks: artifacts.internalLinkProbes.length,
        brokenLinks: brokenInternalLinks.length,
        locations: brokenLinkLocations(brokenInternalLinks),
      },
    }),
  );

  const brokenExternalLinks = artifacts.externalLinkProbes.filter(
    (probe) => !isSuccessfulStatus(probe.status),
  );
  const externalBrokenStatus =
    artifacts.externalLinkProbes.length === 0
      ? { status: "info" as const, severity: "info" as const }
      : brokenExternalLinks.length === 0
        ? { status: "pass" as const, severity: "info" as const }
        : { status: "warning" as const, severity: "low" as const };
  findings.push(
    buildSeoCheck({
      checkKey: "broken-external-links",
      title: "Broken external links",
      ...externalBrokenStatus,
      shortDescription:
        artifacts.externalLinkProbes.length === 0
          ? "No external links were sampled during the limited crawl."
          : brokenExternalLinks.length === 0
            ? `No broken external links were detected across ${artifacts.externalLinkProbes.length} sampled URLs.`
            : `${brokenExternalLinks.length} of ${artifacts.externalLinkProbes.length} sampled external links returned errors.`,
      whyItMatters:
        "Broken external references hurt user trust and can weaken the perceived quality of the page.",
      recommendation:
        artifacts.externalLinkProbes.length === 0 || brokenExternalLinks.length === 0
          ? "Keep external references reviewed periodically."
          : "Update or remove external links that now return errors.",
      evidence: {
        ...pageEvidence(
          primaryPage,
          "External links discovered during the limited crawl",
          artifacts.externalLinkProbes.length === 0
            ? "No external links were available for sampling."
            : brokenExternalLinks.length === 0
              ? "All sampled external links returned successful or redirected responses."
              : "Some sampled external links returned errors.",
        ),
        sampledLinks: artifacts.externalLinkProbes.length,
        brokenLinks: brokenExternalLinks.length,
        locations: brokenLinkLocations(brokenExternalLinks),
      },
    }),
  );

  const duplicateTitleLocations = findDuplicateValues(crawledPages, (page) => page.title, "Title");
  const duplicateDescriptionLocations = findDuplicateValues(
    crawledPages,
    (page) => page.description,
    "Description",
  );
  const duplicateLocations = [...duplicateTitleLocations, ...duplicateDescriptionLocations];
  findings.push(
    buildSeoCheck({
      checkKey: "duplicate-like-metadata",
      title: "Duplicate-like metadata",
      status: duplicateLocations.length > 0 ? "warning" : "pass",
      severity: duplicateLocations.length > 0 ? "low" : "info",
      shortDescription:
        duplicateLocations.length > 0
          ? "Repeated titles or descriptions were found across the limited crawl."
          : `No duplicate titles or descriptions were found across ${crawledPages.length} crawled pages.`,
      whyItMatters:
        "Repeated metadata makes pages harder to distinguish in search results and can dilute relevance signals.",
      recommendation:
        duplicateLocations.length > 0
          ? "Make repeated titles and descriptions more specific to each page."
          : "Keep metadata unique as new pages are added.",
      evidence: {
        ...pageEvidence(
          primaryPage,
          "Title and meta description values across crawled pages",
          duplicateLocations.length > 0
            ? "Some crawled pages reused the same title or description."
            : "The limited crawl did not detect duplicate title or description values.",
        ),
        crawledPages: crawledPages.length,
        duplicateCount: duplicateLocations.length,
        locations: duplicateLocations.slice(0, 8),
      },
    }),
  );

  const gated = applyPremiumGating(findings, 8);
  return {
    score: computeScore(findings),
    findings: gated,
  };
}
