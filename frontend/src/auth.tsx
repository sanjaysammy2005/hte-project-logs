import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, getToken, onUnauthorized, setToken } from "./api/client";
import type { Operator, Role } from "./api/types";

type AuthState = {
  operator: Operator | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  can: (...roles: Role[]) => boolean;
};

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [operator, setOperator] = useState<Operator | null>(null);
  const [loading, setLoading] = useState(true);

  const clear = useCallback(() => {
    setToken(null);
    setOperator(null);
  }, []);

  useEffect(() => {
    onUnauthorized(clear);
    if (!getToken()) {
      setLoading(false);
      return;
    }
    api<Operator>("/auth/me")
      .then(setOperator)
      .catch(clear)
      .finally(() => setLoading(false));
    return () => onUnauthorized(null);
  }, [clear]);

  const login = useCallback(async (username: string, password: string) => {
    const token = await api<{ access_token: string }>("/auth/login", {
      method: "POST",
      body: { username, password },
    });
    setToken(token.access_token);
    setOperator(await api<Operator>("/auth/me"));
  }, []);

  const logout = useCallback(async () => {
    try {
      await api("/auth/logout", { method: "POST" });
    } finally {
      clear();
    }
  }, [clear]);

  const can = useCallback((...roles: Role[]) => !!operator && roles.includes(operator.role), [operator]);

  return <AuthContext.Provider value={{ operator, loading, login, logout, can }}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}
