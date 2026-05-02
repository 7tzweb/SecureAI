export type AuthContext = {
  id: string;
  label: "anonymous" | "userA" | "userB" | "admin" | string;
  cookies?: Array<{ name: string; value: string; domain?: string; path?: string }>;
  headers?: Record<string, string>;
  token?: string | null;
  userId?: string | number | null;
  email?: string | null;
  role?: string | null;
};

function headersToRecord(headers: HeadersInit | undefined): Record<string, string> {
  if (!headers) {
    return {};
  }
  if (headers instanceof Headers) {
    return Object.fromEntries(headers.entries());
  }
  if (Array.isArray(headers)) {
    return Object.fromEntries(headers.map(([key, value]) => [key, value]));
  }
  return Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key, String(value)]),
  );
}

export function authContextFromSession(input: {
  id: string;
  label: string;
  headers?: HeadersInit;
  token?: string | null;
  userId?: string | number | null;
  email?: string | null;
  role?: string | null;
}): AuthContext {
  const headers = headersToRecord(input.headers);
  const cookieHeader = headers.cookie ?? headers.Cookie ?? "";
  const cookies = cookieHeader
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const [name, ...rest] = part.split("=");
      return {
        name: name.trim(),
        value: rest.join("=").trim(),
        path: "/",
      };
    })
    .filter((cookie) => cookie.name && cookie.value);

  return {
    id: input.id,
    label: input.label,
    headers,
    cookies,
    token: input.token ?? null,
    userId: input.userId ?? null,
    email: input.email ?? null,
    role: input.role ?? null,
  };
}

export class AuthContextStore {
  private readonly contexts = new Map<string, AuthContext>();

  upsert(context: AuthContext) {
    this.contexts.set(context.id, context);
    return context;
  }

  get(id: string) {
    return this.contexts.get(id) ?? null;
  }

  all() {
    return [...this.contexts.values()];
  }

  byLabel(label: string) {
    return this.all().find((context) => context.label === label) ?? null;
  }
}
