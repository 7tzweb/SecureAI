import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { SiteHeader } from "@/components/layout/site-header";
import { AuthProvider } from "@/components/providers/auth-provider";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: {
    default: "fixnx",
    template: "%s | fixnx",
  },
  description:
    "fixnx scans websites for security, SEO, and performance issues with a fast async workflow.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      data-scroll-behavior="smooth"
      className={`${inter.variable} h-full scroll-smooth antialiased`}
    >
      <body className="min-h-full bg-[var(--page-bg)] text-[var(--ink)]">
        <AuthProvider>
          <SiteHeader />
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
