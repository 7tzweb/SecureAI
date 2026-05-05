export type AccountIdentity = {
  uid: string;
  email: string | null | undefined;
};

export function normalizeAccountEmail(email: string | null | undefined) {
  const normalized = email?.trim().toLowerCase() ?? "";
  return normalized || null;
}

export function accountEmailsMatch(
  left: string | null | undefined,
  right: string | null | undefined,
) {
  const normalizedLeft = normalizeAccountEmail(left);
  const normalizedRight = normalizeAccountEmail(right);
  return Boolean(normalizedLeft && normalizedLeft === normalizedRight);
}
