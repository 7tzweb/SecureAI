import IORedis from "ioredis";
import { Queue } from "bullmq";
import { categoryKeys } from "@/lib/types";
import { hasRedisConfig, serverConfig } from "@/server/config";
import { serviceUnavailable } from "@/server/api/errors";
import { type QueueDriver } from "@/server/queue/types";

let queue: Queue | null = null;
let connection: IORedis | null = null;

function getConnection() {
  if (!hasRedisConfig) {
    throw serviceUnavailable("Redis is not configured for BullMQ.");
  }

  if (!connection) {
    connection = new IORedis(serverConfig.redisUrl, {
      maxRetriesPerRequest: null,
      enableReadyCheck: false,
    });
  }

  return connection;
}

function getQueue() {
  if (!queue) {
    queue = new Queue("cyberaudit-scans", {
      connection: getConnection(),
    });
  }

  return queue;
}

export function createBullMqQueueDriver(): QueueDriver {
  return {
    async enqueueScan(scanId) {
      const queue = getQueue();
      await Promise.all(
        categoryKeys.map((category) =>
          queue.add(
            category,
            {
              scanId,
              category,
            },
            {
              jobId: `${scanId}:${category}`,
              removeOnComplete: 100,
              removeOnFail: 100,
              attempts: 2,
              backoff: {
                type: "exponential",
                delay: 1_500,
              },
            },
          ),
        ),
      );
    },
  };
}

export function getBullMqConnection() {
  return getConnection();
}
