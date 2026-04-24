import { type CategoryKey } from "@/lib/types";

export interface CategoryJobPayload {
  scanId: string;
  category: CategoryKey;
}

export interface QueueDriver {
  enqueueScan(scanId: string): Promise<void>;
}
