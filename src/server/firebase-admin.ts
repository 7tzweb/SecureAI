import "server-only";

import { readFileSync } from "node:fs";
import { cert, getApps, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";
import { hasFirebaseAdminConfig, serverConfig } from "@/server/config";

export function getFirebaseAdminApp() {
  if (!hasFirebaseAdminConfig) {
    throw new Error("Firebase Admin configuration is missing.");
  }

  if (getApps().length) {
    return getApps()[0]!;
  }

  if (serverConfig.firebaseServiceAccountResolvedPath) {
    const serviceAccount = JSON.parse(
      readFileSync(serverConfig.firebaseServiceAccountResolvedPath, "utf8"),
    ) as {
      project_id?: string;
      client_email?: string;
      private_key?: string;
    };

    return initializeApp({
      credential: cert({
        projectId: serviceAccount.project_id ?? serverConfig.firebaseProjectId,
        clientEmail: serviceAccount.client_email ?? serverConfig.firebaseClientEmail,
        privateKey: serviceAccount.private_key ?? serverConfig.firebasePrivateKey,
      }),
    });
  }

  return initializeApp({
    credential: cert({
      projectId: serverConfig.firebaseProjectId,
      clientEmail: serverConfig.firebaseClientEmail,
      privateKey: serverConfig.firebasePrivateKey,
    }),
  });
}

export function getFirebaseAdminAuth() {
  return getAuth(getFirebaseAdminApp());
}

export function getFirebaseAdminDb() {
  return getFirestore(getFirebaseAdminApp());
}
