/** Navigation per role. This only mirrors the backend's role checks so users are not shown
 *  places that would refuse them; the backend still enforces every endpoint on its own.
 *  Items without a backend yet are marked ``planned`` and say so on their page. */

import type { Role } from "../api/types";
import { SYSTEM_STREAM_ID } from "../api/zt";

export type NavItem = { to: string; label: string; icon: string; planned?: boolean; end?: boolean };
export type NavSection = { title?: string; items: NavItem[] };

const S = `/audit/streams/${SYSTEM_STREAM_ID}`;

export function navFor(role: Role): NavSection[] {
  if (role === "ingestor") return [];
  const security = role === "admin" || role === "auditor";
  const fileOwner = role !== "auditor";
  const sections: NavSection[] = [
    { items: [{ to: "/overview", label: "Overview", icon: "overview" }] },
    {
      title: "Files",
      items: [
        { to: "/files", label: "All files", icon: "files", end: true },
        ...(fileOwner
          ? [
              { to: "/files/mine", label: "My files", icon: "mine" },
              { to: "/files/shared", label: "Shared with me", icon: "shared" },
            ]
          : []),
        { to: "/files/recent", label: "Recent", icon: "recent" },
        { to: "/files/trash", label: "Trash", icon: "trash" },
      ],
    },
  ];
  if (security) {
    sections.push(
      {
        title: "Security",
        items: [
          { to: "/security/findings", label: "Findings", icon: "findings" },
          { to: "/security/denied", label: "Denied access", icon: "denied" },
          { to: "/security/integrity", label: "File integrity", icon: "integrity" },
          { to: "/security/events", label: "Security events", icon: "events", end: true },
          ...(role === "admin"
            ? [
                { to: "/security/policies", label: "Access policies", icon: "policy", planned: true },
                { to: "/security/requests", label: "Access requests", icon: "requests", planned: true },
              ]
            : []),
        ],
      },
      {
        title: "Audit",
        items: [
          { to: `${S}/events`, label: "Events", icon: "audit" },
          { to: `${S}/chain`, label: "Hash chain", icon: "chain" },
          { to: `${S}/batches`, label: "Merkle batches", icon: "merkle" },
          { to: `${S}/verification`, label: "Verification", icon: "verify" },
          { to: "/audit/streams", label: "All streams", icon: "streams", end: true },
        ],
      },
      {
        title: "Research",
        items: [
          ...(role === "admin" ? [{ to: "/research/lab", label: "Tamper lab", icon: "lab" }] : []),
          { to: "/research/experiments", label: "Experiments", icon: "experiments" },
        ],
      },
    );
  }
  if (role === "admin") {
    sections.push({
      title: "Administration",
      items: [
        { to: "/admin/users", label: "Users", icon: "users" },
        { to: "/admin/roles", label: "Roles", icon: "roles", planned: true },
        { to: "/admin/permissions", label: "Permissions", icon: "permissions", planned: true },
        { to: "/admin/settings", label: "System settings", icon: "settings", planned: true },
      ],
    });
  }
  return sections;
}

/** Roles that may create files (policy file: workspace CREATE). */
export function canCreateFiles(role: Role): boolean {
  return role === "admin" || role === "manager" || role === "employee";
}
