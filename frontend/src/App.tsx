import { Suspense, lazy, type ReactNode } from "react";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router";
import { AppShell } from "./app/AppShell";
import { AuthProvider, useAuth } from "./auth";
import { PlannedPage, UsersPage } from "./features/admin/AdminPages";
import FileDetailPage from "./features/files/FileDetailPage";
import FilesPage from "./features/files/FilesPage";
import OverviewPage from "./features/overview/OverviewPage";
import EventInvestigationPage from "./features/security/EventInvestigationPage";
import FileInvestigationPage from "./features/security/FileInvestigationPage";
import FindingsPage from "./features/security/FindingsPage";
import SecurityEventsPage from "./features/security/SecurityEventsPage";
import LabPage from "./pages/LabPage";
import LoginPage from "./pages/LoginPage";
import { BatchesPage, ChainPage, EventDetailPage, EventsPage, SessionPage, StreamLayout, VerificationPage } from "./pages/StreamPages";
import StreamsPage from "./pages/StreamsPage";
import type { Role } from "./api/types";
import { AccessGuardProvider } from "./ui/access";
import { ToastProvider } from "./ui/feedback";
import { EmptyState, Skeleton } from "./ui/primitives";

// Plotly is large, so the experiments page is loaded only when visited.
const ExperimentsPage = lazy(() => import("./pages/ExperimentsPage"));

function Protected({ children, roles }: { children: ReactNode; roles?: Role[] }) {
  const { operator, loading } = useAuth();
  if (loading)
    return (
      <div className="page" aria-busy="true">
        <Skeleton width={240} height={20} />
      </div>
    );
  if (!operator) return <Navigate to="/login" replace />;
  if (operator.role === "ingestor") {
    return (
      <div className="page">
        <EmptyState title="No dashboard access">Ingestor accounts can only submit events through the API.</EmptyState>
      </div>
    );
  }
  if (roles && !roles.includes(operator.role)) {
    // Mirrors the backend's role check; the backend refuses these APIs on its own anyway.
    return (
      <AppShell>
        <EmptyState title="Not available for your role">This area is for {roles.join(" and ")} accounts.</EmptyState>
      </AppShell>
    );
  }
  return <AppShell>{children}</AppShell>;
}

/** Old URLs keep working: /streams/... → /audit/streams/..., /lab, /experiments. */
function LegacyRedirect({ to }: { to: string }) {
  const location = useLocation();
  const rest = location.pathname.replace(/^\/streams/, "");
  return <Navigate to={to === "streams" ? `/audit/streams${rest}${location.search}` : to} replace />;
}

const SEC: Role[] = ["admin", "auditor"];

export default function App() {
  return (
    <AuthProvider>
      <ToastProvider>
        <AccessGuardProvider>
          <BrowserRouter>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/" element={<Navigate to="/overview" replace />} />
              <Route path="/overview" element={<Protected><OverviewPage /></Protected>} />

              <Route path="/files" element={<Protected><FilesPage key="all" scope="all" /></Protected>} />
              <Route path="/files/mine" element={<Protected><FilesPage key="mine" scope="mine" /></Protected>} />
              <Route path="/files/shared" element={<Protected><FilesPage key="shared" scope="shared" /></Protected>} />
              <Route path="/files/recent" element={<Protected><FilesPage key="recent" scope="recent" /></Protected>} />
              <Route path="/files/trash" element={<Protected><FilesPage key="trash" scope="trash" /></Protected>} />
              <Route path="/files/:fileId" element={<Protected><FileDetailPage /></Protected>} />

              <Route path="/security/findings" element={<Protected roles={SEC}><FindingsPage /></Protected>} />
              <Route path="/security/denied" element={<Protected roles={SEC}><SecurityEventsPage key="denied" preset="denied" /></Protected>} />
              <Route path="/security/integrity" element={<Protected roles={SEC}><SecurityEventsPage key="integrity" preset="integrity" /></Protected>} />
              <Route path="/security/events" element={<Protected roles={SEC}><SecurityEventsPage key="all" /></Protected>} />
              <Route path="/security/events/:chainIndex" element={<Protected roles={SEC}><EventInvestigationPage /></Protected>} />
              <Route path="/security/files/:fileId" element={<Protected roles={SEC}><FileInvestigationPage /></Protected>} />
              <Route path="/security/policies" element={<Protected roles={["admin"]}><PlannedPage which="policies" /></Protected>} />
              <Route path="/security/requests" element={<Protected roles={["admin"]}><PlannedPage which="requests" /></Protected>} />

              <Route path="/audit/streams" element={<Protected roles={SEC}><StreamsPage /></Protected>} />
              <Route path="/audit/streams/:streamId" element={<Protected roles={SEC}><StreamLayout /></Protected>}>
                <Route index element={<Navigate to="events" replace />} />
                <Route path="events" element={<EventsPage />} />
                <Route path="events/:chainIndex" element={<EventDetailPage />} />
                <Route path="chain" element={<ChainPage />} />
                <Route path="sessions/:sessionId" element={<SessionPage />} />
                <Route path="batches" element={<BatchesPage />} />
                <Route path="verification" element={<VerificationPage />} />
              </Route>

              <Route path="/research/lab" element={<Protected roles={["admin"]}><LabPage /></Protected>} />
              <Route
                path="/research/experiments"
                element={
                  <Protected roles={SEC}>
                    <Suspense fallback={<Skeleton height={200} />}>
                      <ExperimentsPage />
                    </Suspense>
                  </Protected>
                }
              />

              <Route path="/admin/users" element={<Protected roles={["admin"]}><UsersPage /></Protected>} />
              <Route path="/admin/roles" element={<Protected roles={["admin"]}><PlannedPage which="roles" /></Protected>} />
              <Route path="/admin/permissions" element={<Protected roles={["admin"]}><PlannedPage which="permissions" /></Protected>} />
              <Route path="/admin/settings" element={<Protected roles={["admin"]}><PlannedPage which="settings" /></Protected>} />

              <Route path="/streams/*" element={<LegacyRedirect to="streams" />} />
              <Route path="/lab" element={<Navigate to="/research/lab" replace />} />
              <Route path="/experiments" element={<Navigate to="/research/experiments" replace />} />
              <Route path="*" element={<Navigate to="/overview" replace />} />
            </Routes>
          </BrowserRouter>
        </AccessGuardProvider>
      </ToastProvider>
    </AuthProvider>
  );
}
