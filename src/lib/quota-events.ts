export const QUOTA_REFRESH_EVENT = "cyberaudit:quota-refresh";

export function dispatchQuotaRefresh() {
  if (typeof window === "undefined") {
    return;
  }

  window.dispatchEvent(new Event(QUOTA_REFRESH_EVENT));
}

export function subscribeQuotaRefresh(listener: () => void) {
  if (typeof window === "undefined") {
    return () => {};
  }

  window.addEventListener(QUOTA_REFRESH_EVENT, listener);
  return () => {
    window.removeEventListener(QUOTA_REFRESH_EVENT, listener);
  };
}
