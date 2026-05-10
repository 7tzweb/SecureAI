export const scanPacks = [
  { scans: 20, priceUsd: 4.99 },
  { scans: 50, priceUsd: 9.99 },
  { scans: 120, priceUsd: 19.9 },
] as const;

export const defaultScanPack = scanPacks[0];

export function getScanPack(scans: number) {
  return scanPacks.find((pack) => pack.scans === scans) ?? null;
}

export function isScanPackSize(scans: number) {
  return Boolean(getScanPack(scans));
}
