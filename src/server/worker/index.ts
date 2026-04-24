import { Worker } from "bullmq";
import { hasRedisConfig } from "@/server/config";
import { getBullMqConnection } from "@/server/queue/bullmq-driver";
import { processCategoryJob } from "@/server/queue/processor";
import { type CategoryJobPayload } from "@/server/queue/types";

async function main() {
  if (!hasRedisConfig) {
    throw new Error("REDIS_URL is required to run the BullMQ worker.");
  }

  const worker = new Worker(
    "cyberaudit-scans",
    async (job) => {
      const payload = job.data as CategoryJobPayload;
      await processCategoryJob(payload.scanId, payload.category);
    },
    {
      connection: getBullMqConnection(),
      concurrency: 6,
    },
  );

  worker.on("completed", (job) => {
    console.log(`Completed ${job.name} for ${job.id}`);
  });

  worker.on("failed", (job, error) => {
    console.error(`Failed ${job?.name ?? "unknown job"}:`, error);
  });

  console.log("CyberAudit BullMQ worker is listening for jobs.");
}

void main();
