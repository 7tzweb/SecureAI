import "server-only";

import { hasRedisConfig } from "@/server/config";
import { createBullMqQueueDriver } from "@/server/queue/bullmq-driver";
import { createLocalQueueDriver } from "@/server/queue/local-driver";
import { type QueueDriver } from "@/server/queue/types";

let queueDriver: QueueDriver | null = null;

export function getQueueDriver() {
  if (!queueDriver) {
    queueDriver = hasRedisConfig ? createBullMqQueueDriver() : createLocalQueueDriver();
  }

  return queueDriver;
}
