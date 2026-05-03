export type FooterSectionKey =
  | "PRODUCT"
  | "SECURITY TESTS"
  | "SOLUTIONS"
  | "RESOURCES"
  | "COMPARE"
  | "COMPANY";

export type MarketingPage = {
  href: string;
  footerLabel: string;
  section: FooterSectionKey;
  title: string;
  metaTitle: string;
  metaDescription: string;
  kicker: string;
  lead: string;
  intro: string;
  bestFor: string[];
  checks: string[];
  outcomes: string[];
  articleTitle: string;
  article: string[];
  faq: Array<{
    question: string;
    answer: string;
  }>;
};

const productPages: MarketingPage[] = [
  {
    href: "/website-vulnerability-scanner",
    footerLabel: "Vulnerability Scanner",
    section: "PRODUCT",
    title: "Website Vulnerability Scanner",
    metaTitle: "Website Vulnerability Scanner",
    metaDescription:
      "Run a fast website vulnerability scanner for public security risks, exposed files, risky headers, authentication issues, and clear remediation guidance.",
    kicker: "Website security",
    lead:
      "Find the website risks that are easiest to miss when a site moves fast: unsafe headers, exposed files, injection signals, auth weaknesses, and public attack surface.",
    intro:
      "A useful vulnerability scanner should do more than list warnings. Fixnx turns public website checks into a readable security report with evidence, priority, and next steps your team can act on.",
    bestFor: ["Marketing sites", "SaaS dashboards", "Customer portals", "Pre-launch reviews"],
    checks: ["Public attack surface", "SQL injection signals", "XSS indicators", "Security headers", "Sensitive files", "Session evidence"],
    outcomes: ["Understand what is exposed", "Prioritize confirmed risks", "Share a readable report", "Track fixes after deployment"],
    articleTitle: "Why website vulnerability scanning should be part of every release",
    article: [
      "Most website incidents start with small public mistakes: a forgotten backup file, a weak login route, a missing browser protection, or an API endpoint that reveals more than expected. A scan gives teams a practical way to see those problems before users or attackers do.",
      "Fixnx is designed for fast feedback. It separates confirmed issues from likely signals, explains evidence clearly, and keeps low-impact hardening items from drowning out the risks that should be fixed first.",
      "Use this page as a launch point before a release, after a major frontend change, or whenever a new domain becomes public.",
    ],
    faq: [
      {
        question: "Is a website vulnerability scanner the same as a penetration test?",
        answer:
          "No. A scanner gives fast, repeatable coverage for common public risks. A manual penetration test adds deeper business logic testing and human validation.",
      },
      {
        question: "Can I scan a live production website?",
        answer:
          "Yes. Fixnx uses bounded checks designed for live websites. Deep or authenticated scans should still be scoped carefully.",
      },
    ],
  },
  {
    href: "/web-security-scanner",
    footerLabel: "Web Scanner",
    section: "PRODUCT",
    title: "Web Security Scanner",
    metaTitle: "Web Security Scanner for Modern Websites",
    metaDescription:
      "Use Fixnx as a web security scanner for headers, browser protections, authentication surface, exposed resources, and actionable website security reports.",
    kicker: "Web security",
    lead:
      "Scan the browser-facing parts of your website and understand which weaknesses matter before they become support tickets or security incidents.",
    intro:
      "Modern web apps combine static assets, APIs, sessions, redirects, and third-party scripts. Fixnx reviews the visible web surface and turns technical signals into practical recommendations.",
    bestFor: ["Web apps", "Product teams", "Agencies", "Public launch checks"],
    checks: ["Browser-rendered pages", "Headers", "Cookies", "Forms", "API routes", "Client-side exposure"],
    outcomes: ["Catch public misconfigurations", "Improve browser security", "Reduce noisy findings", "Export a professional report"],
    articleTitle: "What a web security scanner should explain",
    article: [
      "A good web security scanner should tell a story: what was tested, what was proven, what is only suspicious, and what should happen next. Without that structure, teams waste time arguing about noisy results.",
      "Fixnx keeps the report focused on concrete risk. Confirmed vulnerabilities are separated from likely findings and informational coverage notes, so teams can fix the highest-impact issues first.",
      "Run a scan when new pages, APIs, authentication changes, or third-party scripts are deployed.",
    ],
    faq: [
      {
        question: "What does a web security scanner check first?",
        answer:
          "It starts with public pages, browser behavior, headers, forms, exposed files, and discovered API routes.",
      },
      {
        question: "Why do some findings stay likely instead of confirmed?",
        answer:
          "Fixnx only marks exploitability as confirmed when the scan collected proof. Strong signals without proof stay likely.",
      },
    ],
  },
  {
    href: "/api-security-scanner",
    footerLabel: "API Scanner",
    section: "PRODUCT",
    title: "API Security Scanner",
    metaTitle: "API Security Scanner",
    metaDescription:
      "Discover API endpoints, classify sensitive routes, test common API risks, and produce clear evidence for public and authenticated API security issues.",
    kicker: "API security",
    lead:
      "Find API routes that expose sensitive data, accept risky input, or behave differently across anonymous and authenticated contexts.",
    intro:
      "APIs are often shipped faster than documentation. Fixnx discovers routes from browser traffic, links, JavaScript, and common paths, then classifies what each endpoint appears to handle.",
    bestFor: ["REST APIs", "SaaS APIs", "Internal dashboards", "SPA backends"],
    checks: ["Endpoint discovery", "Sensitive route classification", "Auth surface", "ID parameters", "CORS behavior", "Response evidence"],
    outcomes: ["See discovered API surface", "Identify sensitive endpoints", "Separate public from protected routes", "Improve API hardening"],
    articleTitle: "API security starts with knowing what is reachable",
    article: [
      "Many API risks are not hidden in complex exploits. They come from endpoints that were meant to be internal, debug routes left exposed, or user-owned resources that do not enforce authorization consistently.",
      "Fixnx helps by showing the discovered API surface, classifying endpoint purpose, and attaching evidence to high-risk findings. That makes it easier to talk about API security with developers and product owners.",
      "Use API scanning after frontend releases, backend route changes, and authentication refactors.",
    ],
    faq: [
      {
        question: "Does Fixnx discover API endpoints automatically?",
        answer:
          "Yes. It samples browser traffic, page links, forms, JavaScript hints, and common API paths within scope.",
      },
      {
        question: "Can API authorization be fully proven without login contexts?",
        answer:
          "No. Full cross-user proof needs separate user contexts, such as userA and userB sessions.",
      },
    ],
  },
  {
    href: "/attack-surface-scanner",
    footerLabel: "Attack Surface",
    section: "PRODUCT",
    title: "Attack Surface Scanner",
    metaTitle: "Attack Surface Scanner",
    metaDescription:
      "Map public pages, APIs, forms, sensitive endpoints, headers, JavaScript assets, and likely security risks with a fast attack surface scanner.",
    kicker: "Attack surface",
    lead:
      "Understand what your website exposes to an outside visitor: pages, APIs, parameters, headers, sensitive files, and high-value routes.",
    intro:
      "Attack surface is the security inventory attackers see first. Fixnx turns that inventory into a report that shows coverage depth and risk priority.",
    bestFor: ["New domains", "Product launches", "Security reviews", "Vendor checks"],
    checks: ["Crawled pages", "Discovered endpoints", "Forms and inputs", "Sensitive files", "Admin-like paths", "Technology hints"],
    outcomes: ["Map public exposure", "Spot unexpected routes", "Prioritize sensitive endpoints", "Document scan coverage"],
    articleTitle: "A smaller attack surface is easier to defend",
    article: [
      "Teams cannot protect routes they do not know about. An attack surface scan gives a practical map of the public website and the API signals that appear during rendering.",
      "Fixnx keeps the scan bounded so it is useful during normal work. It reports how many pages, endpoints, parameters, and active probes were covered, which makes the result easier to trust.",
      "Use this scan before a launch, before onboarding a customer, or when you inherit an existing website.",
    ],
    faq: [
      {
        question: "What is attack surface scanning?",
        answer:
          "It is the process of mapping reachable pages, endpoints, inputs, files, and configuration signals that could be attacked.",
      },
      {
        question: "Does attack surface scanning prove every vulnerability?",
        answer:
          "No. It maps exposure and highlights risks. Some findings need active proof or authenticated testing.",
      },
    ],
  },
  {
    href: "/security-headers-scanner",
    footerLabel: "Headers Scanner",
    section: "PRODUCT",
    title: "Security Headers Scanner",
    metaTitle: "Security Headers Scanner",
    metaDescription:
      "Check HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, content type protection, and other browser security headers.",
    kicker: "Browser protection",
    lead:
      "Check whether your website sends the browser security headers that reduce clickjacking, MIME sniffing, downgrade, and data leakage risk.",
    intro:
      "Security headers are not a substitute for secure code, but they are a strong baseline. Fixnx reports missing and weak headers without letting header-only issues outrank confirmed exploitable vulnerabilities.",
    bestFor: ["Hardening reviews", "Compliance prep", "Frontend teams", "Launch checks"],
    checks: ["HSTS", "Content Security Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"],
    outcomes: ["Improve browser controls", "Reduce clickjacking risk", "Document hardening gaps", "Avoid header noise"],
    articleTitle: "Security headers are a baseline, not the whole story",
    article: [
      "Headers help browsers enforce safer behavior, but a missing header should not be treated the same as confirmed SQL injection or authentication bypass. Priority matters.",
      "Fixnx checks the common browser protections and explains what they do in plain language. The report keeps hardening recommendations useful while still prioritizing higher-impact vulnerabilities.",
      "Use this page when you want a quick header review before sending a site to customers or auditors.",
    ],
    faq: [
      {
        question: "Which security header matters most?",
        answer:
          "It depends on the app. HSTS and CSP are often important, but the right priority depends on exposure and confirmed risks.",
      },
      {
        question: "Can headers fix vulnerable application code?",
        answer:
          "No. Headers reduce browser-side risk, but server-side vulnerabilities still need code and configuration fixes.",
      },
    ],
  },
  {
    href: "/free-website-security-check",
    footerLabel: "Free Check",
    section: "PRODUCT",
    title: "Free Website Security Check",
    metaTitle: "Free Website Security Check",
    metaDescription:
      "Run a free website security check for public risks, security headers, exposed files, SEO issues, and performance signals in one fast report.",
    kicker: "Free scan",
    lead:
      "Start with a fast public check that gives you a readable snapshot of website security, SEO, and performance health.",
    intro:
      "A free check is the easiest way to find obvious public issues before they become expensive. Fixnx gives quick feedback without requiring a long setup process.",
    bestFor: ["First-time scans", "Small businesses", "Side projects", "Pre-sales checks"],
    checks: ["Public website access", "Headers", "Exposed files", "Basic injection signals", "SEO basics", "Performance hints"],
    outcomes: ["Know where to start", "Share a simple report", "Find quick wins", "Decide if deeper testing is needed"],
    articleTitle: "Start with the risks visible from the outside",
    article: [
      "You do not need a full security program to start improving your website. A public security check can find missing protections, exposed files, and obvious configuration mistakes quickly.",
      "Fixnx keeps the first report readable. It shows what passed, what failed, and what needs more proof before being treated as confirmed.",
      "Run a free check whenever you launch a new site, change hosting, or connect a new domain.",
    ],
    faq: [
      {
        question: "What does the free website security check include?",
        answer:
          "It includes public website checks across security, SEO, and performance with bounded scan depth.",
      },
      {
        question: "Do I need to install anything?",
        answer:
          "No. Enter a website URL and Fixnx runs the check from outside the site.",
      },
    ],
  },
];

const securityTestPages: MarketingPage[] = [
  {
    href: "/owasp-top-10-scanner",
    footerLabel: "OWASP Scanner",
    section: "SECURITY TESTS",
    title: "OWASP Top 10 Scanner",
    metaTitle: "OWASP Top 10 Scanner",
    metaDescription:
      "Scan a website for OWASP Top 10 risk areas including injection, XSS, access control, authentication, misconfiguration, and sensitive exposure.",
    kicker: "OWASP Top 10",
    lead:
      "Review the most common web application risk categories with a report that separates confirmed evidence from likely signals.",
    intro:
      "The OWASP Top 10 is a practical way to talk about web application risk. Fixnx maps scan results into categories teams already understand, while keeping proof and confidence visible.",
    bestFor: ["Security baselines", "Audit prep", "Developer education", "Release checks"],
    checks: ["Injection", "XSS", "Access control", "Authentication", "Security misconfiguration", "Sensitive exposure"],
    outcomes: ["Use familiar risk language", "Find high-priority issues", "Document evidence", "Guide remediation"],
    articleTitle: "Using OWASP Top 10 as a practical checklist",
    article: [
      "OWASP is useful because it gives teams a shared language. But checklists become noisy when every item looks equally urgent.",
      "Fixnx keeps the OWASP-style view practical by showing severity, confidence, evidence, and recommended first fixes. That helps teams move from awareness to action.",
      "Use this scanner to create a security baseline before deeper manual testing.",
    ],
    faq: [
      {
        question: "Does this replace an OWASP manual review?",
        answer:
          "No. It gives fast coverage for common risk areas and helps decide where manual review should focus.",
      },
      {
        question: "Are all OWASP categories actively exploited by the scanner?",
        answer:
          "No. Some checks are active, while others are coverage notes or likely signals depending on available proof.",
      },
    ],
  },
  {
    href: "/sql-injection-scanner",
    footerLabel: "SQL Injection",
    section: "SECURITY TESTS",
    title: "SQL Injection Scanner",
    metaTitle: "SQL Injection Scanner",
    metaDescription:
      "Test public parameters for SQL injection signals with baseline comparisons, payload evidence, response differences, and clear confidence labels.",
    kicker: "Injection testing",
    lead:
      "Check whether search, filter, login, and ID parameters behave like backend queries can be manipulated.",
    intro:
      "SQL injection remains one of the clearest signs that application input is reaching a database unsafely. Fixnx looks for measurable response changes and reports evidence carefully.",
    bestFor: ["Search endpoints", "Login routes", "Filter parameters", "Legacy apps"],
    checks: ["Baseline response", "Payload response", "Record count differences", "SQL error signals", "Boolean behavior", "Safe limits"],
    outcomes: ["Find injection candidates", "See payload evidence", "Prioritize confirmed findings", "Add regression tests"],
    articleTitle: "SQL injection proof should be measurable",
    article: [
      "A scanner should not call SQL injection confirmed because a page looks suspicious. It should show what changed: status, response shape, record count, timing, or error behavior.",
      "Fixnx reports SQL injection with evidence summaries and keeps weaker signals marked as likely. That helps developers reproduce the issue without overstating proof.",
      "Use this check especially on search, login, and API filter routes.",
    ],
    faq: [
      {
        question: "What makes SQL injection confirmed?",
        answer:
          "Confirmed SQL injection requires measurable proof such as stable response differences, query errors, record expansion, or verified blind behavior.",
      },
      {
        question: "Are the payloads destructive?",
        answer:
          "No. Fixnx uses bounded, controlled payloads intended for safe validation.",
      },
    ],
  },
  {
    href: "/xss-scanner",
    footerLabel: "XSS",
    section: "SECURITY TESTS",
    title: "XSS Scanner",
    metaTitle: "XSS Scanner",
    metaDescription:
      "Scan for reflected, stored, and DOM XSS indicators, persistence, and browser execution evidence with clear confirmed versus likely labels.",
    kicker: "Browser security",
    lead:
      "Check whether user-controlled input can appear in pages, persist in content, or execute in the browser.",
    intro:
      "XSS risk is easy to overstate if a scanner only sees reflection. Fixnx separates indicators, persistence, and browser execution so teams know what was actually proven.",
    bestFor: ["Search pages", "Comments", "Reviews", "Profile fields", "SPA routes"],
    checks: ["Input reflection", "Stored marker persistence", "DOM sinks", "Browser execution signals", "Context-aware evidence", "Safe markers"],
    outcomes: ["Reduce XSS false confidence", "Find risky render paths", "Prioritize execution proof", "Guide encoding fixes"],
    articleTitle: "XSS needs context, not just payload lists",
    article: [
      "A payload reflected into text is not the same as browser-side JavaScript execution. Treating them the same creates false confidence and noisy reports.",
      "Fixnx uses confidence labels so stored-but-not-executed findings stay likely, while browser execution evidence is required for confirmed XSS.",
      "Use this scanner after adding search, rich text, reviews, comments, or user profile features.",
    ],
    faq: [
      {
        question: "Why is stored XSS sometimes marked likely?",
        answer:
          "If a marker is stored and retrieved but browser execution is not observed, Fixnx reports it as likely rather than confirmed.",
      },
      {
        question: "What should developers fix first?",
        answer:
          "Fix confirmed execution first, then review persistent and reflected likely signals with output encoding and sanitization.",
      },
    ],
  },
  {
    href: "/idor-scanner",
    footerLabel: "IDOR",
    section: "SECURITY TESTS",
    title: "IDOR Scanner",
    metaTitle: "IDOR Scanner",
    metaDescription:
      "Find object identifier authorization risks and distinguish likely IDOR signals from confirmed cross-user ownership proof.",
    kicker: "Authorization",
    lead:
      "Detect routes where object IDs can be changed and understand whether cross-user access was actually proven.",
    intro:
      "IDOR testing needs more than a 200 response. Fixnx reports ID mutation as likely unless separate user contexts prove that one user accessed another user's object.",
    bestFor: ["Baskets", "Orders", "Invoices", "Profiles", "Reports"],
    checks: ["ID-based URLs", "Object mutation", "Session-aware probes", "Ownership markers", "UserA/UserB proof", "Response comparison"],
    outcomes: ["Find authorization candidates", "Avoid false confirmation", "Know when user contexts are needed", "Improve object-level checks"],
    articleTitle: "A real IDOR finding needs ownership proof",
    article: [
      "Changing an ID and receiving 200 is a signal, not proof. The response might be public, empty, or scoped correctly.",
      "Fixnx keeps that distinction visible. Confirmed IDOR requires evidence that one user accessed data owned by another user.",
      "For best results, provide userA and userB sessions so the scanner can compare ownership boundaries.",
    ],
    faq: [
      {
        question: "Why was my IDOR finding likely instead of confirmed?",
        answer:
          "Because the scan observed successful ID mutation but did not prove cross-user ownership exposure.",
      },
      {
        question: "How do I confirm IDOR?",
        answer:
          "Provide two separate authenticated user contexts so the scanner can test user-owned resources across accounts.",
      },
    ],
  },
  {
    href: "/authentication-security-testing",
    footerLabel: "Auth Testing",
    section: "SECURITY TESTS",
    title: "Authentication Security Testing",
    metaTitle: "Authentication Security Testing",
    metaDescription:
      "Review login surfaces, authentication bypass signals, token handling, session reuse, password routes, and protected endpoint verification.",
    kicker: "Authentication",
    lead:
      "Test the routes that decide who gets in, how sessions are created, and whether authentication proof can be reused against protected endpoints.",
    intro:
      "Authentication issues can change the entire risk picture. Fixnx verifies reusable context before calling authentication bypass confirmed.",
    bestFor: ["Login pages", "Account portals", "SaaS apps", "Admin dashboards"],
    checks: ["Login endpoint discovery", "Bypass payload response", "Token extraction", "Protected endpoint verification", "Session model", "Password route signals"],
    outcomes: ["Find login risks", "Understand token-based auth", "Separate cookies from tokens", "Enable authenticated scanning"],
    articleTitle: "Authentication evidence must prove access",
    article: [
      "A token-looking response is not enough. A strong authentication finding should show that the scanner reused the artifact against a protected endpoint.",
      "Fixnx reports login endpoint, payload preview, response status, session artifact type, verification endpoint, and authentication model with masked secrets.",
      "Use this page when a site has login, account areas, or admin functionality.",
    ],
    faq: [
      {
        question: "What confirms authentication bypass?",
        answer:
          "Fixnx requires a successful bypass response and protected endpoint verification using the resulting session or token.",
      },
      {
        question: "Are tokens shown in the report?",
        answer:
          "No. Tokens are masked and only short previews are displayed.",
      },
    ],
  },
  {
    href: "/ssl-tls-security-check",
    footerLabel: "SSL/TLS",
    section: "SECURITY TESTS",
    title: "SSL & TLS Security Check",
    metaTitle: "SSL and TLS Security Check",
    metaDescription:
      "Check HTTPS availability, certificate validity, HTTP to HTTPS behavior, HSTS, insecure forms, and mixed content risk signals.",
    kicker: "Transport security",
    lead:
      "Confirm that visitors reach your website over HTTPS and that the browser gets the right signals to keep traffic protected.",
    intro:
      "TLS problems are often easy to fix but costly when missed. Fixnx checks the public transport layer and highlights browser-facing weaknesses.",
    bestFor: ["New domains", "Hosting migrations", "Compliance checks", "Launch readiness"],
    checks: ["HTTPS response", "Certificate validity", "HTTP redirect", "HSTS", "Mixed content", "Insecure forms"],
    outcomes: ["Catch transport gaps", "Improve browser trust", "Reduce downgrade risk", "Document HTTPS posture"],
    articleTitle: "TLS checks are a launch requirement",
    article: [
      "Users expect HTTPS everywhere. Search engines, browsers, and customers all treat broken transport security as a trust issue.",
      "Fixnx checks whether HTTPS works, whether HTTP redirects safely, and whether page content creates insecure browser behavior.",
      "Run this check after DNS changes, CDN changes, certificate renewals, and hosting migrations.",
    ],
    faq: [
      {
        question: "Does SSL/TLS scanning check the certificate?",
        answer:
          "Yes. Fixnx checks public HTTPS behavior and certificate-related signals available during the scan.",
      },
      {
        question: "Is HSTS always required?",
        answer:
          "HSTS is a strong protection for HTTPS sites, but it should be enabled carefully once HTTPS is stable.",
      },
    ],
  },
];

const solutionPages: MarketingPage[] = [
  {
    href: "/solutions/developers",
    footerLabel: "Developers",
    section: "SOLUTIONS",
    title: "Fixnx for Developers",
    metaTitle: "Website Security Scanning for Developers",
    metaDescription:
      "Give developers fast, readable website security reports with evidence, priority, and remediation guidance that fits release workflows.",
    kicker: "For developers",
    lead:
      "Find issues early, understand the evidence, and fix the highest-impact risks without waiting for a long manual review.",
    intro:
      "Developers need security feedback that is specific enough to act on and calm enough to trust. Fixnx focuses on proof, confidence, and practical remediation.",
    bestFor: ["Pre-release checks", "Pull request review support", "Bug triage", "Security baselines"],
    checks: ["Headers", "APIs", "Auth routes", "XSS signals", "SQLi evidence", "Sensitive exposure"],
    outcomes: ["Reduce security rework", "Ship safer changes", "Create regression tests", "Explain fixes clearly"],
    articleTitle: "Security reports developers can actually use",
    article: [
      "A useful developer security report should show where the issue is, what evidence was collected, and what change is likely to fix it.",
      "Fixnx avoids treating every signal as confirmed. That makes the output easier to trust and easier to turn into engineering tasks.",
      "Use Fixnx before releases, after authentication changes, and when new public endpoints are added.",
    ],
    faq: [
      {
        question: "Can developers use Fixnx without security expertise?",
        answer:
          "Yes. Findings include plain-language summaries, evidence, risk priority, and recommended fixes.",
      },
      {
        question: "Does Fixnx create noisy reports?",
        answer:
          "The report separates confirmed vulnerabilities, likely issues, and informational notes to reduce noise.",
      },
    ],
  },
  {
    href: "/solutions/saas",
    footerLabel: "SaaS",
    section: "SOLUTIONS",
    title: "Fixnx for SaaS Companies",
    metaTitle: "SaaS Website and API Security Scanner",
    metaDescription:
      "Help SaaS teams monitor public web and API risk, authentication surface, customer-facing routes, and security evidence before customers ask.",
    kicker: "For SaaS",
    lead:
      "Protect the web app, marketing site, login surface, and customer-facing API routes that SaaS buyers inspect first.",
    intro:
      "SaaS security is not only about infrastructure. Customers judge your product by login security, exposed APIs, browser posture, and how quickly your team can answer risk questions.",
    bestFor: ["Customer portals", "Trial signups", "APIs", "Security questionnaires"],
    checks: ["Login routes", "Public APIs", "Headers", "Session model", "Attack surface", "Sensitive endpoints"],
    outcomes: ["Prepare for customer review", "Find public risk quickly", "Improve security posture", "Support sales conversations"],
    articleTitle: "SaaS buyers notice public security signals",
    article: [
      "Before a formal review, buyers often look at the basics: HTTPS, headers, exposed routes, login behavior, and whether public APIs appear controlled.",
      "Fixnx gives SaaS teams a fast way to inspect those signals and produce a report that product, engineering, and security teams can understand together.",
      "Use it before enterprise deals, major launches, and security questionnaire cycles.",
    ],
    faq: [
      {
        question: "Can Fixnx help with security questionnaires?",
        answer:
          "It can support answers about public website posture, scan coverage, and remediation priorities, but it does not replace formal compliance evidence.",
      },
      {
        question: "Should SaaS teams run authenticated scans?",
        answer:
          "Yes, when possible. Authenticated mode gives stronger coverage for protected endpoints and authorization behavior.",
      },
    ],
  },
  {
    href: "/solutions/startups",
    footerLabel: "Startups",
    section: "SOLUTIONS",
    title: "Fixnx for Startups",
    metaTitle: "Fast Website Security Scanner for Startups",
    metaDescription:
      "Give startups a fast way to check website security, public API risk, SEO basics, and performance before launches, demos, and customer reviews.",
    kicker: "For startups",
    lead:
      "Move quickly without ignoring the risks that customers, investors, and early users will notice.",
    intro:
      "Startups do not always have time for a full security program on day one. Fixnx gives a practical first layer of website security visibility.",
    bestFor: ["Launch week", "Investor demos", "First customers", "Small engineering teams"],
    checks: ["Public security", "Headers", "Login surface", "Exposed files", "SEO basics", "Performance signals"],
    outcomes: ["Find quick wins", "Avoid obvious mistakes", "Share progress", "Plan deeper testing"],
    articleTitle: "Startups need security feedback that fits the pace",
    article: [
      "The goal is not to slow the team down. The goal is to catch the public mistakes that are cheap to fix now and expensive to explain later.",
      "Fixnx gives startups a simple path: scan, read the top risks, fix what matters, and rerun the report.",
      "Use it before product launches, public demos, and the first enterprise conversations.",
    ],
    faq: [
      {
        question: "Is this enough for enterprise security review?",
        answer:
          "It is a strong starting point, but enterprise reviews may also require policies, compliance documents, and manual testing.",
      },
      {
        question: "Can non-security founders read the report?",
        answer:
          "Yes. The report is written to be clear for founders, developers, and security reviewers.",
      },
    ],
  },
  {
    href: "/solutions/security-teams",
    footerLabel: "Security Teams",
    section: "SOLUTIONS",
    title: "Fixnx for Security Teams",
    metaTitle: "Website Security Scanner for Security Teams",
    metaDescription:
      "Help security teams triage public web risk, validate evidence, track attack surface, and share professional reports with engineering teams.",
    kicker: "For security teams",
    lead:
      "Give security teams a fast way to inspect public web risk and focus deeper review on the issues that show evidence.",
    intro:
      "Security teams need clarity: what is confirmed, what is likely, what was not covered, and what should be fixed first. Fixnx is built around that separation.",
    bestFor: ["Triage", "External surface review", "Engineering handoff", "Repeat scans"],
    checks: ["Confirmed exploitability", "Likely high-impact issues", "Attack path summary", "Access matrix", "Session model", "Endpoint inventory"],
    outcomes: ["Reduce triage time", "Improve handoff quality", "Track coverage", "Prioritize based on proof"],
    articleTitle: "Security triage improves when confidence is explicit",
    article: [
      "A high-severity label is not enough. Security teams need to know whether the scanner proved impact or only found a strong signal.",
      "Fixnx makes confidence part of the report model. That keeps confirmed vulnerabilities separate from supporting evidence and coverage notes.",
      "Use Fixnx to prioritize external review and give engineers a focused list of fixes.",
    ],
    faq: [
      {
        question: "Can security teams export reports?",
        answer:
          "Yes. Fixnx generates downloadable reports with evidence, priority, attack path, session model, and discovered surface sections.",
      },
      {
        question: "Does Fixnx support authenticated testing?",
        answer:
          "Yes. Authenticated scan mode can use provided context for protected endpoint and authorization testing.",
      },
    ],
  },
  {
    href: "/solutions/devops",
    footerLabel: "DevOps",
    section: "SOLUTIONS",
    title: "Fixnx for DevOps Teams",
    metaTitle: "Website Security Checks for DevOps Teams",
    metaDescription:
      "Help DevOps teams verify HTTPS, headers, exposed files, deployment changes, public endpoints, and performance signals after releases.",
    kicker: "For DevOps",
    lead:
      "Check the website after deployments, infrastructure changes, DNS updates, CDN changes, and certificate renewals.",
    intro:
      "Many web security issues come from deployment and configuration drift. Fixnx gives DevOps teams a fast external check after changes go live.",
    bestFor: ["Deployments", "CDN changes", "DNS changes", "Certificate renewals", "Release validation"],
    checks: ["HTTPS behavior", "Headers", "Exposed files", "Server hints", "API routes", "Performance basics"],
    outcomes: ["Catch drift", "Verify production behavior", "Document release checks", "Reduce rollback risk"],
    articleTitle: "External checks catch what internal config misses",
    article: [
      "A config can look correct in code and still behave differently once CDN rules, redirects, headers, and hosting layers are involved.",
      "Fixnx checks the live website from the outside, which makes it useful after infrastructure changes and public releases.",
      "Use it as a quick post-deploy validation step for public web properties.",
    ],
    faq: [
      {
        question: "Can Fixnx check after every deployment?",
        answer:
          "Yes. Fast mode is designed for quick, bounded checks after public changes.",
      },
      {
        question: "What deployment risks does it catch?",
        answer:
          "It can catch missing headers, transport issues, exposed files, unexpected public endpoints, and performance regressions.",
      },
    ],
  },
];

const resourcePages: MarketingPage[] = [
  {
    href: "/blog",
    footerLabel: "Blog",
    section: "RESOURCES",
    title: "Fixnx Blog",
    metaTitle: "Fixnx Blog",
    metaDescription:
      "Read practical articles about website security, API testing, vulnerability scanning, remediation, SEO, and performance for modern teams.",
    kicker: "Resources",
    lead:
      "Practical writing for teams that want to understand website security without getting lost in jargon.",
    intro:
      "The Fixnx blog is built around useful, shareable security explanations: how to interpret findings, how to prioritize fixes, and how to avoid common public website mistakes.",
    bestFor: ["Security awareness", "Founder education", "Developer enablement", "Content planning"],
    checks: ["Security explainers", "Remediation notes", "Scanner guides", "Release checklists", "API articles", "SEO basics"],
    outcomes: ["Learn faster", "Share clear posts", "Educate teams", "Turn findings into content"],
    articleTitle: "Security content should make action easier",
    article: [
      "Good security writing does not need to sound complex. It should help a team understand what happened, why it matters, and what to do next.",
      "Use the Fixnx blog as a source for practical posts about web risk, scanning, remediation, and security habits that real teams can adopt.",
      "Each article is written to be useful for founders, developers, and security reviewers.",
    ],
    faq: [
      {
        question: "What topics does the blog cover?",
        answer:
          "Website security, vulnerability scanning, API security, remediation, SEO, performance, and release readiness.",
      },
      {
        question: "Can I share these articles with non-technical teams?",
        answer:
          "Yes. The content is written to be clear and practical for mixed audiences.",
      },
    ],
  },
  {
    href: "/guides",
    footerLabel: "Guides",
    section: "RESOURCES",
    title: "Security Guides",
    metaTitle: "Website Security Guides",
    metaDescription:
      "Explore practical website security guides covering checklists, OWASP Top 10, API security, remediation, and scan report interpretation.",
    kicker: "Guides",
    lead:
      "Clear guides for website owners, developers, and security teams who want practical next steps.",
    intro:
      "Security guides should be easy to apply. Fixnx guides focus on actions: what to check, what evidence means, and how to reduce risk.",
    bestFor: ["Team training", "Security planning", "Launch prep", "Remediation workflows"],
    checks: ["Checklists", "Risk categories", "API guidance", "Remediation", "Security headers", "Authentication"],
    outcomes: ["Create better habits", "Plan reviews", "Educate teams", "Improve reports"],
    articleTitle: "Use guides to turn scan results into habits",
    article: [
      "A scan tells you what was found today. A guide helps your team avoid the same issue next month.",
      "The Fixnx guide collection is designed to pair with scan reports so teams can move from finding to fix to prevention.",
      "Start with the website checklist if you are preparing a launch, or the remediation guide if you already have findings.",
    ],
    faq: [
      {
        question: "Where should I start?",
        answer:
          "Start with the Website Security Checklist for public sites or the API Security Checklist for backend-heavy applications.",
      },
      {
        question: "Are the guides technical?",
        answer:
          "They are practical and readable, with enough technical detail to help developers take action.",
      },
    ],
  },
  {
    href: "/guides/website-security-checklist",
    footerLabel: "Security Checklist",
    section: "RESOURCES",
    title: "Website Security Checklist",
    metaTitle: "Website Security Checklist",
    metaDescription:
      "Use this website security checklist to review HTTPS, headers, authentication, exposed files, API routes, XSS, SQL injection, and remediation priorities.",
    kicker: "Checklist",
    lead:
      "A practical checklist for reviewing a public website before launch, after changes, or before a customer review.",
    intro:
      "The best checklist is one your team will actually use. This one focuses on public risks that can be checked quickly and discussed clearly.",
    bestFor: ["Launch readiness", "Monthly reviews", "Client sites", "Security handoffs"],
    checks: ["HTTPS", "Headers", "Exposed files", "Login surface", "API endpoints", "Input handling"],
    outcomes: ["Standardize reviews", "Catch common issues", "Document fixes", "Prepare deeper testing"],
    articleTitle: "A simple website security checklist",
    article: [
      "Start with transport security: HTTPS should work, HTTP should redirect safely, and forms should not submit over insecure connections.",
      "Then review browser protections, public files, login routes, API endpoints, and user input. The goal is not perfection in one pass; it is repeatable improvement.",
      "Use Fixnx to automate the first pass and keep the checklist connected to evidence.",
    ],
    faq: [
      {
        question: "How often should I run a website security checklist?",
        answer:
          "Run it before major releases, after hosting changes, and periodically for public websites.",
      },
      {
        question: "What should I fix first?",
        answer:
          "Fix confirmed exploitable vulnerabilities first, then likely high-impact issues, then hardening items.",
      },
    ],
  },
  {
    href: "/guides/api-security-checklist",
    footerLabel: "API Checklist",
    section: "RESOURCES",
    title: "API Security Checklist",
    metaTitle: "API Security Checklist",
    metaDescription:
      "Review API security with a checklist for authentication, authorization, object IDs, sensitive endpoints, CORS, tokens, schemas, and exposed debug routes.",
    kicker: "Checklist",
    lead:
      "Use this checklist to review the API routes your frontend, customers, and integrations depend on.",
    intro:
      "API security is strongest when teams review discovery, authorization, authentication, data exposure, and error behavior together.",
    bestFor: ["REST APIs", "SaaS backends", "Frontend teams", "Security reviews"],
    checks: ["Authentication", "Authorization", "IDOR", "CORS", "Tokens", "Debug routes"],
    outcomes: ["Map endpoints", "Protect user data", "Improve token handling", "Reduce exposure"],
    articleTitle: "API security checklist for public apps",
    article: [
      "Start by listing the API routes that are reachable from the browser. If you cannot describe what each route does, it is hard to defend it.",
      "Next, test whether routes require the right authentication, enforce object-level authorization, avoid exposing sensitive fields, and handle errors safely.",
      "Fixnx helps by discovering and classifying API endpoints, then attaching evidence to security findings.",
    ],
    faq: [
      {
        question: "What is the most common API security issue?",
        answer:
          "Broken authorization is common, especially around user-owned resources such as baskets, orders, invoices, and profiles.",
      },
      {
        question: "Do I need authenticated scans for API testing?",
        answer:
          "Authenticated scans give stronger coverage for protected routes and cross-user authorization checks.",
      },
    ],
  },
  {
    href: "/guides/owasp-top-10",
    footerLabel: "OWASP Guide",
    section: "RESOURCES",
    title: "OWASP Top 10 Guide",
    metaTitle: "OWASP Top 10 Guide",
    metaDescription:
      "A plain-English OWASP Top 10 guide for understanding injection, XSS, access control, authentication, misconfiguration, and security logging risks.",
    kicker: "OWASP guide",
    lead:
      "Understand OWASP Top 10 categories in practical language that connects directly to website and API scan findings.",
    intro:
      "OWASP is most useful when it helps teams decide what to do next. This guide explains the categories through examples teams see in real reports.",
    bestFor: ["Developer training", "Security onboarding", "Audit prep", "Risk communication"],
    checks: ["Injection", "Access control", "Authentication", "Security misconfiguration", "Sensitive exposure", "Logging gaps"],
    outcomes: ["Understand categories", "Improve prioritization", "Talk with stakeholders", "Plan fixes"],
    articleTitle: "OWASP Top 10 in plain language",
    article: [
      "The OWASP Top 10 is not a magic checklist, but it is a helpful map of the risks that appear repeatedly in web applications.",
      "Use it to organize findings, not to replace evidence. A confirmed authentication bypass should outrank a low-impact header warning even if both appear in a security report.",
      "Fixnx aligns scan output with this practical approach: proof first, priority second, explanation always.",
    ],
    faq: [
      {
        question: "Is OWASP Top 10 only for security teams?",
        answer:
          "No. Developers, founders, DevOps teams, and product leaders can use it to understand common web application risk.",
      },
      {
        question: "Does passing an OWASP scan mean my app is secure?",
        answer:
          "No single scan proves full security. It improves coverage and helps prioritize deeper review.",
      },
    ],
  },
  {
    href: "/guides/vulnerability-remediation",
    footerLabel: "Remediation",
    section: "RESOURCES",
    title: "Vulnerability Remediation Guide",
    metaTitle: "Vulnerability Remediation Guide",
    metaDescription:
      "Learn how to prioritize, fix, verify, and communicate website vulnerability remediation using evidence, confidence, risk, and retesting.",
    kicker: "Remediation",
    lead:
      "Turn security findings into a clear fix plan: prioritize, assign, remediate, retest, and document what changed.",
    intro:
      "Remediation works best when teams agree on evidence and priority. Fixnx reports are structured to make that handoff easier.",
    bestFor: ["Engineering teams", "Security triage", "Customer assurance", "Release planning"],
    checks: ["Confirmed risks", "Likely issues", "Supporting evidence", "Top fixes", "Attack paths", "Retest readiness"],
    outcomes: ["Fix the right issues first", "Reduce repeated bugs", "Communicate clearly", "Verify remediation"],
    articleTitle: "How to remediate vulnerabilities without losing focus",
    article: [
      "Start with confirmed exploitable vulnerabilities, especially public unauthenticated issues and anything that grants authenticated access or exposes data.",
      "Next, review likely high-impact issues. They may need more proof, but they often point to risky code paths or authorization boundaries.",
      "After fixes are deployed, rerun the scan and compare evidence. Remediation is complete only when the risky behavior no longer appears.",
    ],
    faq: [
      {
        question: "What should remediation teams fix first?",
        answer:
          "Fix confirmed critical and high vulnerabilities first, especially issues that enable attack paths.",
      },
      {
        question: "Should low-risk findings be ignored?",
        answer:
          "No, but they should not outrank confirmed exploitable issues. Schedule hardening after urgent fixes.",
      },
    ],
  },
];

const comparePages: MarketingPage[] = [
  {
    href: "/compare/manual-pentest",
    footerLabel: "Manual Pentest",
    section: "COMPARE",
    title: "Fixnx vs Manual Pentest",
    metaTitle: "Fixnx vs Manual Penetration Testing",
    metaDescription:
      "Compare Fixnx automated website security scanning with manual penetration testing, including speed, depth, cost, evidence, and when to use both.",
    kicker: "Compare",
    lead:
      "Use Fixnx for fast repeatable coverage, and use manual penetration testing for deeper human-led business logic review.",
    intro:
      "Automated scanning and manual testing solve different problems. The strongest teams use both at the right time.",
    bestFor: ["Pre-pentest cleanup", "Continuous checks", "Budget planning", "Security roadmap"],
    checks: ["Coverage speed", "Evidence clarity", "Business logic depth", "Retesting", "Cost", "Repeatability"],
    outcomes: ["Choose the right approach", "Reduce pentest noise", "Prepare better scopes", "Retest faster"],
    articleTitle: "Automated scanning and manual testing work best together",
    article: [
      "A manual pentest can find complex business logic issues that scanners may miss. But it is usually slower, more expensive, and less frequent.",
      "Fixnx helps teams clean up public issues before a pentest and rerun checks after fixes. That makes manual testing time more valuable.",
      "Use Fixnx continuously and bring in manual testers for high-risk releases, compliance, and deep application review.",
    ],
    faq: [
      {
        question: "Does Fixnx replace a manual pentest?",
        answer:
          "No. It complements manual testing with fast, repeatable public and authenticated scan coverage.",
      },
      {
        question: "When should I run Fixnx before a pentest?",
        answer:
          "Run it before scoping and again after remediation to reduce obvious findings and verify fixes.",
      },
    ],
  },
  {
    href: "/compare/vulnerability-scanner",
    footerLabel: "Scanner",
    section: "COMPARE",
    title: "Fixnx vs Vulnerability Scanner",
    metaTitle: "Fixnx vs Traditional Vulnerability Scanner",
    metaDescription:
      "Compare Fixnx with traditional vulnerability scanners and learn how confidence labels, attack paths, evidence, and readable reports improve triage.",
    kicker: "Compare",
    lead:
      "Traditional scanners often produce long lists. Fixnx focuses on evidence, confidence, and recommended first fixes.",
    intro:
      "The difference is not just what gets checked. It is how the result is explained and prioritized.",
    bestFor: ["Scanner replacement review", "Security triage", "Report quality", "Founder-friendly output"],
    checks: ["Confirmed vs likely", "Top fixes", "Attack path", "Session model", "Access matrix", "PDF reporting"],
    outcomes: ["Reduce noise", "Improve trust", "Prioritize faster", "Share better reports"],
    articleTitle: "Why scanner reports need better product thinking",
    article: [
      "A scanner can be technically correct and still hard to use. If every finding looks urgent, teams stop trusting the report.",
      "Fixnx separates confirmed vulnerabilities from likely issues and supporting evidence. That makes the report more useful for engineering and business conversations.",
      "Use this comparison when evaluating tools for public website and API scanning.",
    ],
    faq: [
      {
        question: "What makes Fixnx different?",
        answer:
          "Fixnx emphasizes proof, confidence, risk scoring, attack path narrative, and readable reporting.",
      },
      {
        question: "Can Fixnx import findings from other scanners?",
        answer:
          "This page focuses on Fixnx native scans. Import workflows depend on future product support.",
      },
    ],
  },
  {
    href: "/compare/owasp-zap",
    footerLabel: "OWASP ZAP",
    section: "COMPARE",
    title: "Fixnx vs OWASP ZAP",
    metaTitle: "Fixnx vs OWASP ZAP",
    metaDescription:
      "Compare Fixnx with OWASP ZAP for website scanning, report clarity, setup effort, active testing, and when developer teams may use each tool.",
    kicker: "Compare",
    lead:
      "OWASP ZAP is powerful and flexible. Fixnx is designed for fast product-style scans and clear reports with less setup.",
    intro:
      "Many teams use ZAP for hands-on testing and Fixnx for quick external reporting, executive summaries, and recurring website checks.",
    bestFor: ["Tool comparison", "Developer workflows", "Report quality", "Fast scans"],
    checks: ["Setup effort", "Active testing", "Report structure", "Confidence labels", "Authenticated context", "Retesting"],
    outcomes: ["Pick the right tool", "Reduce setup time", "Improve report readability", "Support recurring checks"],
    articleTitle: "ZAP is a toolkit; Fixnx is a report-first scanner",
    article: [
      "OWASP ZAP gives skilled users a broad testing toolkit. It is especially useful when someone wants to manually drive testing and tune behavior.",
      "Fixnx focuses on a simpler workflow: enter a target, run bounded checks, and get a report with recommended fixes and confidence labels.",
      "Teams may use both: ZAP for hands-on testing, Fixnx for fast recurring visibility.",
    ],
    faq: [
      {
        question: "Is Fixnx better than OWASP ZAP?",
        answer:
          "It depends on the workflow. Fixnx prioritizes ease, reporting, and recurring checks; ZAP is a flexible testing toolkit.",
      },
      {
        question: "Do I need security expertise to use Fixnx?",
        answer:
          "Fixnx is designed to be readable for developers, founders, and security teams.",
      },
    ],
  },
  {
    href: "/compare/burp-suite",
    footerLabel: "Burp Suite",
    section: "COMPARE",
    title: "Fixnx vs Burp Suite",
    metaTitle: "Fixnx vs Burp Suite",
    metaDescription:
      "Compare Fixnx with Burp Suite for automated website scanning, manual security testing, workflow complexity, evidence, and reporting.",
    kicker: "Compare",
    lead:
      "Burp Suite is a professional testing platform. Fixnx is a fast website scanner built for clear reports and accessible remediation.",
    intro:
      "Security experts often use Burp for deep manual testing. Product and engineering teams can use Fixnx for quick scan coverage and readable security reporting.",
    bestFor: ["Security teams", "Product teams", "Manual testing", "Automated reports"],
    checks: ["Manual depth", "Automation", "Evidence", "Learning curve", "Report clarity", "Retesting"],
    outcomes: ["Choose workflow fit", "Prepare manual testing", "Communicate fixes", "Retest quickly"],
    articleTitle: "Use the right tool for the job",
    article: [
      "Burp Suite is excellent when a skilled tester wants detailed control. It can support deep testing that goes beyond automated website scans.",
      "Fixnx is built for speed and clarity. It gives teams a fast way to understand public web risk and export a report that non-specialists can read.",
      "For many teams, Fixnx helps clean up public issues before a deeper Burp-driven review.",
    ],
    faq: [
      {
        question: "Does Fixnx replace Burp Suite?",
        answer:
          "No. Burp is stronger for expert manual testing. Fixnx is better for fast, accessible website scans and reports.",
      },
      {
        question: "Can I use both?",
        answer:
          "Yes. Use Fixnx for recurring visibility and Burp for targeted manual testing.",
      },
    ],
  },
];

const companyPages: MarketingPage[] = [
  {
    href: "/about",
    footerLabel: "About",
    section: "COMPANY",
    title: "About Fixnx",
    metaTitle: "About Fixnx",
    metaDescription:
      "Learn about Fixnx, a website security, SEO, and performance scanner built to make security evidence clearer and easier to act on.",
    kicker: "Company",
    lead:
      "Fixnx helps teams understand website security evidence without turning every scan into a noisy checklist.",
    intro:
      "We believe a security report should be clear enough for founders, useful enough for developers, and structured enough for security teams.",
    bestFor: ["Founders", "Developers", "Security teams", "SaaS companies"],
    checks: ["Security", "SEO", "Performance", "Evidence", "Risk scoring", "Reporting"],
    outcomes: ["Clearer decisions", "Faster remediation", "Better conversations", "Repeatable checks"],
    articleTitle: "Why Fixnx exists",
    article: [
      "Security tools often create more confusion than clarity. Fixnx is built around a simple idea: show what was tested, what was proven, and what should be fixed first.",
      "The product combines security, SEO, and performance checks because website teams often need one clear picture before a launch or customer review.",
      "Fixnx is designed for practical work: scan, understand, fix, and retest.",
    ],
    faq: [
      {
        question: "What does Fixnx scan?",
        answer:
          "Fixnx scans websites for public security issues, SEO signals, performance hints, exposed files, headers, and API surface.",
      },
      {
        question: "Who is Fixnx for?",
        answer:
          "Fixnx is for developers, founders, SaaS teams, DevOps teams, and security teams that need readable website risk reports.",
      },
    ],
  },
  {
    href: "/contact",
    footerLabel: "Contact",
    section: "COMPANY",
    title: "Contact Fixnx",
    metaTitle: "Contact Fixnx",
    metaDescription:
      "Contact Fixnx for website security scanning questions, product feedback, billing support, security inquiries, and partnership conversations.",
    kicker: "Contact",
    lead:
      "Need help with a scan, report, billing question, or security workflow? This page explains the best way to reach the team.",
    intro:
      "Good security products should be easy to talk to. Whether you are evaluating Fixnx or need help interpreting a report, start here.",
    bestFor: ["Product questions", "Report questions", "Billing help", "Security inquiries"],
    checks: ["Scan support", "Report interpretation", "Account questions", "Product feedback", "Partnerships", "Security contact"],
    outcomes: ["Get help faster", "Explain context clearly", "Route requests", "Improve scans"],
    articleTitle: "How to get a useful answer faster",
    article: [
      "When contacting a security product team, include the target domain, scan ID if available, what you expected, and what looked wrong or unclear.",
      "For sensitive reports, avoid sending raw tokens, passwords, or private customer data. Fixnx masks secrets in reports, and support conversations should follow the same habit.",
      "If your request is about a vulnerability in Fixnx itself, use the responsible disclosure page.",
    ],
    faq: [
      {
        question: "What should I include in a scan question?",
        answer:
          "Include the scan ID, target domain, finding title, and a short explanation of what you want to clarify.",
      },
      {
        question: "Where should security disclosures go?",
        answer:
          "Use the Responsible Disclosure page for vulnerabilities affecting Fixnx.",
      },
    ],
  },
  {
    href: "/security",
    footerLabel: "Security",
    section: "COMPANY",
    title: "Fixnx Security",
    metaTitle: "Fixnx Security",
    metaDescription:
      "Learn how Fixnx approaches scanner safety, token masking, bounded testing, SSRF protection, scan scope, and responsible security reporting.",
    kicker: "Security",
    lead:
      "Fixnx is built to scan websites carefully, keep secrets masked, and explain limitations instead of overclaiming proof.",
    intro:
      "A security scanner must be safe itself. Fixnx uses bounded checks, scope controls, masked tokens, and confidence labels to reduce risk.",
    bestFor: ["Security review", "Vendor assessment", "Internal approval", "Scanner safety"],
    checks: ["SSRF guard", "Scope limits", "Token masking", "Safe payloads", "Rate limits", "Confidence labels"],
    outcomes: ["Understand scanner safety", "Review data handling", "Plan authenticated scans", "Share security posture"],
    articleTitle: "Scanner safety is part of product trust",
    article: [
      "Security scanning should not become a source of new risk. Fixnx avoids destructive checks, keeps payloads bounded, and masks sensitive artifacts in reports.",
      "The product also avoids false certainty. Findings are labeled by confidence so users know whether exploitability was confirmed or only suggested.",
      "For authenticated scans, provide only scoped test accounts and rotate credentials when testing is complete.",
    ],
    faq: [
      {
        question: "Does Fixnx store raw tokens?",
        answer:
          "Report output is designed to store and display masked token previews rather than raw secrets.",
      },
      {
        question: "Does Fixnx scan out-of-scope domains?",
        answer:
          "Fixnx is designed to keep scans scoped to the target host unless broader scope is explicitly supported.",
      },
    ],
  },
  {
    href: "/responsible-disclosure",
    footerLabel: "Disclosure",
    section: "COMPANY",
    title: "Responsible Disclosure",
    metaTitle: "Responsible Disclosure",
    metaDescription:
      "Read the Fixnx responsible disclosure guidelines for reporting vulnerabilities safely, clearly, and without exposing user data.",
    kicker: "Disclosure",
    lead:
      "If you believe you found a vulnerability in Fixnx, report it responsibly and avoid accessing or sharing data that is not yours.",
    intro:
      "Responsible disclosure works when both sides keep users safe. This page explains what to include and what to avoid.",
    bestFor: ["Security researchers", "Customers", "Bug reporters", "Vendor review"],
    checks: ["Clear description", "Proof steps", "Affected URL", "Impact", "Safe testing", "No data exposure"],
    outcomes: ["Report safely", "Speed up triage", "Protect users", "Coordinate fixes"],
    articleTitle: "How to write a responsible vulnerability report",
    article: [
      "A useful report explains the affected area, the steps to reproduce, the impact, and the environment. Screenshots or short evidence summaries help, but raw secrets should not be included.",
      "Do not access, modify, delete, or share data that does not belong to you. Avoid denial-of-service testing, social engineering, spam, and persistence.",
      "Fixnx values clear, safe reports that help protect users and improve the product.",
    ],
    faq: [
      {
        question: "What should a disclosure include?",
        answer:
          "Include the affected URL or feature, reproduction steps, expected versus observed behavior, and potential impact.",
      },
      {
        question: "Can I test on other users' data?",
        answer:
          "No. Only test with accounts and data you control.",
      },
    ],
  },
  {
    href: "/privacy",
    footerLabel: "Privacy",
    section: "COMPANY",
    title: "Privacy Policy",
    metaTitle: "Fixnx Privacy Policy",
    metaDescription:
      "Read the Fixnx privacy overview covering scan data, account data, report output, security evidence, billing flows, and data minimization principles.",
    kicker: "Privacy",
    lead:
      "Understand the kinds of data Fixnx may process when you create an account, run a scan, or download a report.",
    intro:
      "Privacy language should be clear. This page summarizes how Fixnx thinks about scan data, account data, report evidence, and sensitive artifact masking.",
    bestFor: ["Customers", "Security reviewers", "Legal review", "Account owners"],
    checks: ["Account data", "Scan targets", "Findings", "Reports", "Billing events", "Masked secrets"],
    outcomes: ["Understand data use", "Review scan sensitivity", "Share privacy posture", "Plan safe testing"],
    articleTitle: "Privacy and website security scanning",
    article: [
      "A scanner may process target URLs, response metadata, findings, scan events, and report evidence. Teams should avoid submitting secrets as target input and should use scoped accounts for authenticated tests.",
      "Fixnx report output is designed to mask sensitive artifacts such as tokens and avoid printing raw secrets.",
      "This page is an informational product overview and should be reviewed alongside any formal legal policy your organization requires.",
    ],
    faq: [
      {
        question: "Does Fixnx need sensitive credentials?",
        answer:
          "Public scans do not. Authenticated scans may use provided scoped credentials or cookies for deeper testing.",
      },
      {
        question: "Are report tokens masked?",
        answer:
          "Yes. The product is designed to display token previews rather than full raw secrets.",
      },
    ],
  },
  {
    href: "/terms",
    footerLabel: "Terms",
    section: "COMPANY",
    title: "Terms of Service",
    metaTitle: "Fixnx Terms of Service",
    metaDescription:
      "Review the Fixnx terms overview for authorized scanning, acceptable use, account responsibility, billing, reports, and safe security testing.",
    kicker: "Terms",
    lead:
      "Use Fixnx only for websites and systems you own or are authorized to test.",
    intro:
      "Security scanning must be scoped and authorized. This page gives a plain-language overview of responsible product use.",
    bestFor: ["Account owners", "Legal review", "Security teams", "Customers"],
    checks: ["Authorized use", "Scan scope", "Account responsibility", "Billing", "Reports", "Abuse prevention"],
    outcomes: ["Use scans safely", "Avoid unauthorized testing", "Set expectations", "Protect accounts"],
    articleTitle: "Safe use matters for every scanner",
    article: [
      "Only scan systems you own or have explicit permission to test. Do not use Fixnx for harassment, denial of service, brute force, spam, or unauthorized access.",
      "Authenticated scans should use scoped test accounts whenever possible. Keep credentials secure and rotate them after testing when appropriate.",
      "This page is a product terms overview and does not replace formal legal review.",
    ],
    faq: [
      {
        question: "Can I scan any website?",
        answer:
          "No. You should scan only websites you own or are authorized to test.",
      },
      {
        question: "Can I use Fixnx for aggressive testing?",
        answer:
          "No. Fixnx is designed for bounded checks, not destructive or denial-of-service behavior.",
      },
    ],
  },
  {
    href: "/status",
    footerLabel: "Status",
    section: "COMPANY",
    title: "Fixnx Status",
    metaTitle: "Fixnx Status",
    metaDescription:
      "Check the Fixnx status overview for scanner availability, report generation, authentication, billing, and background scan processing expectations.",
    kicker: "Status",
    lead:
      "A simple overview of the product areas that matter when scans are queued, running, or generating reports.",
    intro:
      "Status pages are most useful when they explain what users should expect. This page describes the main Fixnx systems and what each one affects.",
    bestFor: ["Scan monitoring", "Support triage", "Customer communication", "Operations"],
    checks: ["Scan queue", "Report generation", "Authentication", "Billing", "Recent scans", "PDF export"],
    outcomes: ["Understand product areas", "Diagnose delays", "Explain scan states", "Plan follow-up"],
    articleTitle: "What Fixnx status should tell you",
    article: [
      "A scan may move through queued, running, partial, completed, or failed states. The most important signal is whether each category has completed or reported an error.",
      "If a scan appears slow, the report should show which category is running and expose console logs with phase information for troubleshooting.",
      "This page is a product overview. A live public status integration can be added when operational monitoring is connected.",
    ],
    faq: [
      {
        question: "Why can a scan take longer than expected?",
        answer:
          "External targets can be slow, block requests, redirect heavily, or delay browser rendering. Fixnx uses bounded timeouts and phase logs.",
      },
      {
        question: "What should I send support?",
        answer:
          "Send the scan ID, target domain, latest phase, and any visible error message.",
      },
    ],
  },
];

export const marketingPages = [
  ...productPages,
  ...securityTestPages,
  ...solutionPages,
  ...resourcePages,
  ...comparePages,
  ...companyPages,
] as const satisfies MarketingPage[];

export const footerSections = [
  "PRODUCT",
  "SECURITY TESTS",
  "SOLUTIONS",
  "RESOURCES",
  "COMPARE",
  "COMPANY",
] as const satisfies FooterSectionKey[];

export function pagesBySection(section: FooterSectionKey) {
  return marketingPages.filter((page) => page.section === section);
}

export function pageByHref(href: string) {
  const normalized = href.endsWith("/") && href !== "/" ? href.slice(0, -1) : href;
  return marketingPages.find((page) => page.href === normalized) ?? null;
}

export function pageBySlug(slug: string[]) {
  return pageByHref(`/${slug.join("/")}`);
}
