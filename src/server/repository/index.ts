import "server-only";

import { serviceUnavailable } from "@/server/api/errors";
import { hasFirebaseAdminConfig, serverConfig } from "@/server/config";
import { createFileRepository } from "@/server/repository/file-store";
import { createFirestoreRepository } from "@/server/repository/firestore-store";
import { type Repository } from "@/server/repository/types";

let repository: Repository | null = null;

export function getRepository() {
  if (repository) {
    return repository;
  }

  if (hasFirebaseAdminConfig) {
    repository = createFirestoreRepository();
    return repository;
  }

  if (serverConfig.nodeEnv === "production") {
    throw serviceUnavailable(
      "Persistent Firestore storage is not configured. Set FIREBASE_SERVICE_ACCOUNT_JSON or a deployed Firebase Admin credentials path before running production billing or scan history.",
    );
  }

  repository = createFileRepository();
  return repository;
}
