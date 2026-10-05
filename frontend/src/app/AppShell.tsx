import {
  Activity,
  BarChart3,
  Ban,
  Boxes,
  ClipboardList,
  Clock,
  Cog,
  FileSearch,
  FileText,
  FlaskConical,
  FolderOpen,
  Gauge,
  KeySquare,
  Layers,
  Link2,
  LogOut,
  Menu as MenuIcon,
  Moon,
  Radar,
  ScrollText,
  Share2,
  ShieldCheck,
  ShieldHalf,
  Sun,
  Trash2,
  User,
  UserCog,
  Users,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router";
import { api } from "../api/client";
import { useAuth } from "../auth";
import { RoleBadge } from "../ui/badges";
import { navFor } from "./nav";
import { useLoader } from "../components";

const ICONS: Record<string, ReactNode> = {
  overview: <Gauge size={16} />,
  files: <FolderOpen size={16} />,
  mine: <User size={16} />,
  shared: <Share2 size={16} />,
  recent: <Clock size={16} />,
  trash: <Trash2 size={16} />,
  findings: <Radar size={16} />,
  denied: <Ban size={16} />,
  integrity: <ShieldCheck size={16} />,
  events: <FileSearch size={16} />,
  policy: <ScrollText size={16} />,
  requests: <ClipboardList size={16} />,
  audit: <Activity size={16} />,
  chain: <Link2 size={16} />,
  merkle: <Layers size={16} />,
  verify: <ShieldHalf size={16} />,
  streams: <Boxes size={16} />,
  lab: <FlaskConical size={16} />,
  experiments: <BarChart3 size={16} />,
  users: <Users size={16} />,
  roles: <UserCog size={16} />,
  permissions: <KeySquare size={16} />,
  settings: <Cog size={16} />,
};

type Theme = "light" | "dark" | null;

function readTheme(): Theme {
  try {
    const t = localStorage.getItem("tracelock.theme");
    return t === "light" || t === "dark" ? t : null;
  } catch {
    return null;
  }
}

function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(readTheme);
  useEffect(() => {
    if (theme) document.documentElement.setAttribute("data-theme", theme);
    else document.documentElement.removeAttribute("data-theme");
  }, [theme]);
  const dark = theme ? theme === "dark" : window.matchMedia?.("(prefers-color-scheme: dark)").matches;
  function toggle() {
    const next = dark ? "light" : "dark";
    setTheme(next);
    try {
      localStorage.setItem("tracelock.theme", next);
    } catch {
      /* per-viewer preference only */
    }
  }
  return (
    <button type="button" className="ghost icon" onClick={toggle} aria-label={dark ? "Switch to light theme" : "Switch to dark theme"} title="Theme">
      {dark ? <Sun size={16} aria-hidden /> : <Moon size={16} aria-hidden />}
    </button>
  );
}

function HealthDot() {
  const health = useLoader(() => api<{ status: string; database: string }>("/health"), []);
  const ok = health.data?.status === "ok";
  return (
    <span className="health hide-narrow" title={health.data ? `API ${health.data.status}, database ${health.data.database}` : "checking"}>
      <span className={`dot ${health.loading ? "" : ok ? "ok" : "bad"}`} aria-hidden />
      {health.loading ? "Checking…" : ok ? "Systems online" : "Degraded"}
    </span>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const { operator, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const location = useLocation();
  useEffect(() => setOpen(false), [location.pathname]);
  if (!operator) return null;
  const sections = navFor(operator.role);
  return (
    <div className={open ? "shell nav-open" : "shell"}>
      <aside className="sidebar" aria-label="Main navigation">
        <div className="sidebar-brand">
          <ShieldCheck size={20} aria-hidden />
          TraceLock
        </div>
        <nav className="nav">
          {sections.map((section, i) => (
            <div key={i} className={section.title ? "nav-section" : undefined}>
              {section.title && <div className="nav-section-title">{section.title}</div>}
              {section.items.map((item) => (
                <NavLink key={item.to} to={item.to} end={item.end}>
                  <span aria-hidden>{ICONS[item.icon] ?? <FileText size={16} />}</span>
                  {item.label}
                  {item.planned && <span className="tag">Planned</span>}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
      </aside>
      <header className="topbar">
        <button type="button" className="ghost icon menu-button" onClick={() => setOpen(!open)} aria-label="Toggle navigation" aria-expanded={open}>
          <MenuIcon size={18} aria-hidden />
        </button>
        <span className="small muted hide-narrow">Context-enriched, tamper-evident audit · Zero-Trust file governance</span>
        <span className="spacer" />
        <HealthDot />
        <ThemeToggle />
        <span className="user-chip" title={`Account ID: ${operator.id}`}>
          <User size={14} aria-hidden />
          <span>{operator.username}</span>
          <RoleBadge role={operator.role} />
        </span>
        <button type="button" className="ghost sm" onClick={() => void logout()}>
          <LogOut size={14} aria-hidden /> Sign out
        </button>
      </header>
      <main className="main" id="main">
        <div className="main-inner">{children}</div>
      </main>
    </div>
  );
}
