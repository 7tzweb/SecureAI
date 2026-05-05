import "server-only";

import { existsSync, readFileSync } from "node:fs";
import { applicationDefault, cert, getApps, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";
import {
  hasFirebaseAdminConfig,
  hasFirebaseApplicationDefaultConfig,
  serverConfig,
} from "@/server/config";

export function getFirebaseAdminApp() {
  if (!hasFirebaseAdminConfig) {
    throw new Error("Firebase Admin configuration is missing.");
  }

  if (getApps().length) {
    return getApps()[0]!;
  }

  if (serverConfig.firebaseClientEmail && serverConfig.firebasePrivateKey) {
    return initializeApp({
      credential: cert({
        projectId: serverConfig.firebaseProjectId,
        clientEmail: serverConfig.firebaseClientEmail,
        privateKey: serverConfig.firebasePrivateKey,
      }),
    });
  }

  if (
    serverConfig.firebaseServiceAccountResolvedPath &&
    existsSync(serverConfig.firebaseServiceAccountResolvedPath)
  ) {
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

  if (hasFirebaseApplicationDefaultConfig) {
    return initializeApp({
      credential: applicationDefault(),
      projectId: serverConfig.firebaseProjectId,
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
