"use client";

import {
  GoogleAuthProvider,
  onIdTokenChanged,
  signInWithPopup,
  signOut as firebaseSignOut,
  type User,
} from "firebase/auth";
import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { getFirebaseAuth } from "@/lib/firebase-client";
import { hasFirebaseClientConfig } from "@/lib/public-config";
import { Button } from "@/components/ui/button";

interface AuthContextValue {
  user: User | null;
  status: "loading" | "signed-in" | "signed-out";
  isConfigured: boolean;
  signInWithGoogle: () => Promise<User>;
  ensureServerSession: () => Promise<User>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

async function syncServerSession(idToken: string) {
  const response = await fetch("/api/auth/session", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ idToken }),
  });

  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new Error(payload?.error ?? "Unable to establish a secure session.");
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [status, setStatus] = useState<"loading" | "signed-in" | "signed-out">(
    hasFirebaseClientConfig ? "loading" : "signed-out",
  );

  useEffect(() => {
    const auth = getFirebaseAuth();
    if (!auth) {
      return;
    }

    const unsubscribe = onIdTokenChanged(auth, (nextUser) => {
      setUser(nextUser);
      setStatus(nextUser ? "signed-in" : "signed-out");
    });

    return unsubscribe;
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      status,
      isConfigured: hasFirebaseClientConfig,
      signInWithGoogle: async () => {
        const auth = getFirebaseAuth();
        if (!auth) {
          throw new Error("Firebase client configuration is missing.");
        }

        const credential = await signInWithPopup(auth, new GoogleAuthProvider());
        const idToken = await credential.user.getIdToken();
        await syncServerSession(idToken);
        return credential.user;
      },
      ensureServerSession: async () => {
        const auth = getFirebaseAuth();
        if (!auth?.currentUser) {
          throw new Error("Google sign-in is required before this session can be synced.");
        }

        const idToken = await auth.currentUser.getIdToken(true);
        await syncServerSession(idToken);
        return auth.currentUser;
      },
      signOut: async () => {
        const auth = getFirebaseAuth();
        if (auth) {
          await firebaseSignOut(auth);
        }

        await fetch("/api/auth/session", { method: "DELETE" });
      },
    }),
    [status, user],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) {
    throw new Error("useAuth must be used within AuthProvider.");
  }

  return value;
}

export function HeaderAuthControls() {
  const { user, status, signInWithGoogle, signOut, isConfigured } = useAuth();

  if (!isConfigured) {
    return (
      <Button variant="outline" size="sm" disabled>
        Google login needs Firebase env
      </Button>
    );
  }

  if (status === "loading") {
    return <div className="h-10 w-40 animate-pulse rounded-2xl bg-slate-200/80" />;
  }

  if (!user) {
    return (
      <Button size="sm" onClick={() => void signInWithGoogle()}>
        Sign in
      </Button>
    );
  }

  return (
    <div className="flex items-center gap-3">
      <div className="hidden text-right md:block">
        <p className="text-sm font-semibold text-[var(--ink)]">
          {user.displayName ?? user.email ?? "Signed in"}
        </p>
        <p className="text-xs text-[var(--ink-soft)]">History and fix access enabled</p>
      </div>
      <Button variant="outline" size="sm" onClick={() => void signOut()}>
        Sign out
      </Button>
    </div>
  );
}
