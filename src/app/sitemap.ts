import type { MetadataRoute } from "next";
import { marketingPages } from "@/lib/marketing-pages";

const siteUrl = process.env.NEXT_PUBLIC_SITE_URL?.replace(/\/$/, "") ?? "https://fixnx.com";

export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date();

  return [
    {
      url: siteUrl,
      lastModified: now,
      changeFrequency: "weekly",
      priority: 1,
    },
    {
      url: `${siteUrl}/history`,
      lastModified: now,
      changeFrequency: "weekly",
      priority: 0.4,
    },
    ...marketingPages.map((page) => ({
      url: `${siteUrl}${page.href}`,
      lastModified: now,
      changeFrequency: "monthly" as const,
      priority: page.section === "PRODUCT" || page.section === "SECURITY TESTS" ? 0.9 : 0.75,
    })),
  ];
}
