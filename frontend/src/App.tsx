import { Suspense, lazy, type ReactNode } from "react";
import { BrowserRouter, Navigate, NavLink, Route, Routes } from "react-router";
import { api } from "./api/client";
import { AuthProvider, useAuth } from "./auth";
import { useLoader } from "./components";
import LabPage from "./pages/LabPage";
import LoginPage from "./pages/LoginPage";
import { BatchesPage, EventDetailPage, EventsPage, SessionPage, StreamLayout, VerificationPage } from "./pages/StreamPages";
import StreamsPage from "./pages/StreamsPage";

// Plotly is large, so the charts page is loaded only when visited.
const ExperimentsPage = lazy(() => import("./pages/ExperimentsPage"));

function HealthDot() {
  const health = useLoader(() => api<{ status: string; database: string }>("/health"), []);
  const ok = health.data?.status === "ok";
  return (
    <span className="health" title={health.data ? `API ${health.data.status}, database ${health.data.database}` : "checking"}>
      <span className={`dot ${health.loading ? "" : ok ? "ok" : "bad"}`} /> {health.loading ? "…" : ok ? "online" : "degraded"}
    </span>
  );
}

function Shell({ children }: { children: ReactNode }) {
  const { operator, logout, can } = useAuth();
  return (
    <>
      <header className="topbar">
        <span className="brand">TraceLock</span>
        <nav>
          <NavLink to="/streams">Streams</NavLink>
          {can("admin") && <NavLink to="/lab">Tamper lab</NavLink>}
          <NavLink to="/experiments">Experiments</NavLink>
        </nav>
        <span className="spacer" />
        <HealthDot />
        <span className="who">
          {operator?.username} <span className="badge muted">{operator?.role}</span>
        </span>
        <button type="button" onClick={() => void logout()}>
          Sign out
        </button>
      </header>
      <main className="page">{children}</main>
    </>
  );
}

function Protected({ children }: { children: ReactNode }) {
  const { operator, loading } = useAuth();
  if (loading) return <p className="page muted">Loading…</p>;
  if (!operator) return <Navigate to="/login" replace />;
  if (operator.role === "ingestor") {
    return (
      <Shell>
        <p>Ingestor accounts can only submit events through the API; they have no dashboard access.</p>
      </Shell>
    );
  }
  return <Shell>{children}</Shell>;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/streams" element={<Protected><StreamsPage /></Protected>} />
          <Route path="/streams/:streamId" element={<Protected><StreamLayout /></Protected>}>
            <Route index element={<Navigate to="events" replace />} />
            <Route path="events" element={<EventsPage />} />
            <Route path="events/:chainIndex" element={<EventDetailPage />} />
            <Route path="sessions/:sessionId" element={<SessionPage />} />
            <Route path="batches" element={<BatchesPage />} />
            <Route path="verification" element={<VerificationPage />} />
          </Route>
          <Route path="/lab" element={<Protected><LabPage /></Protected>} />
          <Route
            path="/experiments"
            element={
              <Protected>
                <Suspense fallback={<p className="muted">Loading charts…</p>}>
                  <ExperimentsPage />
                </Suspense>
              </Protected>
            }
          />
          <Route path="*" element={<Navigate to="/streams" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
