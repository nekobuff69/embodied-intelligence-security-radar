import { describe, it, expect } from "bun:test";
import fixture from "./fixture.json";

import {
  computePatchLag,
  isOpen,
  filterByCategory,
  severityLabel,
  statusLabel,
  statusClass,
  buildItemMap,
} from "../../site/app.js";

// ── Pure helper tests ──────────────────────────────────────────────

describe("computePatchLag", () => {
  it("returns 0 when today equals first_seen", () => {
    expect(computePatchLag("2026-09-09", "2026-09-09")).toBe(0);
  });

  it("counts days correctly", () => {
    expect(computePatchLag("2026-09-01", "2026-09-09")).toBe(8);
  });

  it("handles long durations", () => {
    expect(computePatchLag("2024-08-15", "2026-09-09")).toBe(755);
  });

  it("clamps negative to 0", () => {
    expect(computePatchLag("2026-12-01", "2026-09-09")).toBe(0);
  });
});

describe("isOpen", () => {
  it("returns true for open incidents", () => {
    expect(isOpen({ open: true })).toBe(true);
  });

  it("returns false for closed incidents", () => {
    expect(isOpen({ open: false })).toBe(false);
  });
});

describe("filterByCategory", () => {
  it("filters by category", () => {
    const vulns = filterByCategory(fixture.incidents, "vuln");
    expect(vulns).toHaveLength(1);
    expect(vulns[0].category).toBe("vuln");
  });

  it("returns empty for non-existent category", () => {
    expect(filterByCategory(fixture.incidents, "liability")).toHaveLength(0);
  });
});

describe("severityLabel", () => {
  it("returns CVSS score for cvss source", () => {
    expect(severityLabel({ source: "cvss", value: "8.1" })).toBe("8.1");
  });

  it("appends (estimated) for estimated source", () => {
    expect(severityLabel({ source: "estimated", value: "high" })).toBe(
      "high (estimated)",
    );
  });

  it("returns empty for null", () => {
    expect(severityLabel(null)).toBe("");
  });
});

describe("statusLabel", () => {
  it("maps known states", () => {
    expect(statusLabel("unpatched")).toBe("Unpatched");
    expect(statusLabel("exploited_in_wild")).toBe("Exploited in Wild");
    expect(statusLabel("disclosed")).toBe("Disclosed");
    expect(statusLabel("patched")).toBe("Patched");
    expect(statusLabel("resolved")).toBe("Resolved");
  });

  it("passes through unknown states", () => {
    expect(statusLabel("unknown")).toBe("unknown");
  });
});

describe("statusClass", () => {
  it("returns correct CSS class for each state", () => {
    expect(statusClass("unpatched")).toBe("status-unpatched");
    expect(statusClass("exploited_in_wild")).toBe("status-exploited");
    expect(statusClass("disclosed")).toBe("status-disclosed");
    expect(statusClass("patched")).toBe("status-patched");
    expect(statusClass("resolved")).toBe("status-resolved");
  });
});

describe("buildItemMap", () => {
  it("creates id-keyed map", () => {
    const m = buildItemMap(fixture.items);
    expect(m["itm-fix00000001"]).toBeDefined();
    expect(m["itm-fix00000001"].title).toContain("BLE");
  });

  it("handles empty array", () => {
    expect(buildItemMap([])).toEqual({});
  });
});

// ── Fixture data tests ─────────────────────────────────────────────

describe("fixture structure", () => {
  it("has correct counts", () => {
    expect(fixture.meta.counts.incidents).toBe(3);
    expect(fixture.meta.counts.unpatched).toBe(2);
  });

  it("has correct open flags", () => {
    const byId = Object.fromEntries(
      fixture.incidents.map((i) => [i.id, i]),
    );
    expect(byId["INC-0001"].open).toBe(true);
    expect(byId["INC-0002"].open).toBe(true);
    expect(byId["INC-0003"].open).toBe(true); // disclosed is an open state
  });

  it("all fixture items are attached to incidents (wire empty)", () => {
    const attachedIds = new Set();
    for (const inc of fixture.incidents) {
      for (const id of inc.item_ids) {
        attachedIds.add(id);
      }
    }
    for (const item of fixture.items) {
      expect(attachedIds.has(item.id)).toBe(true);
    }
    expect(fixture.wire).toHaveLength(0);
  });

  it("max_patch_lag_days is 755 for fixture date 2026-09-09", () => {
    expect(fixture.meta.counts.max_patch_lag_days).toBe(755);
  });
});

// ── Patch lag text math ────────────────────────────────────────────

describe("patch lag text", () => {
  it("matches fixture max_patch_lag_days for INC-0001", () => {
    const lag = computePatchLag("2024-08-15", "2026-09-09");
    expect(lag).toBe(755);
    const text = `UNPATCHED FOR ${lag} DAYS`;
    expect(text).toBe("UNPATCHED FOR 755 DAYS");
  });

  it("matches fixture for INC-0002", () => {
    const lag = computePatchLag("2026-08-18", "2026-09-09");
    expect(lag).toBe(22);
    const text = `UNPATCHED FOR ${lag} DAYS`;
    expect(text).toBe("UNPATCHED FOR 22 DAYS");
  });
});
