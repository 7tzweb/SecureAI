"use client";

import { FirebaseApp, getApp, getApps, initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { hasFirebaseClientConfig, publicConfig } from "@/lib/public-config";

let cachedApp: FirebaseApp | null = null;

export function getFirebaseApp() {
  if (!hasFirebaseClientConfig) {
    return null;
  }

  if (cachedApp) {
    return cachedApp;
  }

  cachedApp = getApps().length ? getApp() : initializeApp(publicConfig.firebase);
  return cachedApp;
}

export function getFirebaseAuth() {
  const app = getFirebaseApp();
  return app ? getAuth(app) : null;
}
