import "server-only";

import { hasFirebaseAdminConfig } from "@/server/config";
import { createFileRepository } from "@/server/repository/file-store";
import { createFirestoreRepository } from "@/server/repository/firestore-store";
import { type Repository } from "@/server/repository/types";

let repository: Repository | null = null;

export function getRepository() {
  if (repository) {
    return repository;
  }

  repository = hasFirebaseAdminConfig ? createFirestoreRepository() : createFileRepository();
  return repository;
}
