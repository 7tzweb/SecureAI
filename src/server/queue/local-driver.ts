import { categoryKeys } from "@/lib/types";
import { processCategoryJob } from "@/server/queue/processor";
import { type QueueDriver } from "@/server/queue/types";

export function createLocalQueueDriver(): QueueDriver {
  return {
    async enqueueScan(scanId) {
      categoryKeys.forEach((category, index) => {
        setTimeout(() => {
          void processCategoryJob(scanId, category);
        }, 40 + index * 20);
      });
    },
  };
}
