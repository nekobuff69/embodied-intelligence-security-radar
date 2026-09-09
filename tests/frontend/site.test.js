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
  sortIncidents,
  filterIncidents,
  searchIncidents,
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
    expect(vulns.length).toBeGreaterThanOrEqual(1);
    vulns.forEach((i) => expect(i.category).toBe("vuln"));
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
    expect(fixture.meta.counts.incidents).toBe(6);
    expect(fixture.meta.counts.unpatched).toBe(2); // INC-0001 + INC-0005
  });

  it("has correct open flags", () => {
    const byId = Object.fromEntries(
      fixture.incidents.map((i) => [i.id, i]),
    );
    expect(byId["INC-0001"].open).toBe(true);
    expect(byId["INC-0002"].open).toBe(true);
    expect(byId["INC-0003"].open).toBe(true);
    expect(byId["INC-0004"].open).toBe(false);
    expect(byId["INC-0005"].open).toBe(true);
    expect(byId["INC-0006"].open).toBe(false);
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

// ── sortIncidents tests ───────────────────────────────────────────

describe("sortIncidents", () => {
  describe("newest mode", () => {
    it("sorts by most recent first_seen first", () => {
      const sorted = sortIncidents(fixture.incidents, "newest");
      // INC-0005 (2026-09-01) > INC-0002 (2026-08-18) > INC-0003 (2026-07-01) > ...
      expect(sorted[0].id).toBe("INC-0005");
      expect(sorted[1].id).toBe("INC-0002");
    });

    it("does not mutate original array", () => {
      const orig = [...fixture.incidents];
      sortIncidents(fixture.incidents, "newest");
      expect(fixture.incidents.map((i) => i.id)).toEqual(orig.map((i) => i.id));
    });
  });

  describe("severity mode", () => {
    it("orders CVSS scores first (highest first)", () => {
      const sorted = sortIncidents(fixture.incidents, "severity");
      // CVSS 9.3 (INC-0005) then CVSS 8.1 (INC-0004), then estimated bands
      expect(sorted[0].id).toBe("INC-0005");
      expect(sorted[1].id).toBe("INC-0004");
    });

    it("orders estimated bands: critical > high > medium > low", () => {
      const sorted = sortIncidents(fixture.incidents, "severity");
      // After CVSS: estimated critical (INC-0002) > estimated high (INC-0001) > estimated medium (INC-0003) > estimated low (INC-0006)
      const estIdx = sorted.findIndex((i) => i.id === "INC-0002");
      const highIdx = sorted.findIndex((i) => i.id === "INC-0001");
      const medIdx = sorted.findIndex((i) => i.id === "INC-0003");
      const lowIdx = sorted.findIndex((i) => i.id === "INC-0006");
      expect(estIdx).toBeLessThan(highIdx);
      expect(highIdx).toBeLessThan(medIdx);
      expect(medIdx).toBeLessThan(lowIdx);
    });

    it("breaks ties within same band by most recent first_seen", () => {
      // Create two incidents with same estimated severity
      const same = [
        { id: "A", severity: { source: "estimated", value: "high" }, first_seen: "2026-01-01" },
        { id: "B", severity: { source: "estimated", value: "high" }, first_seen: "2026-06-01" },
      ];
      const sorted = sortIncidents(same, "severity");
      expect(sorted[0].id).toBe("B");
      expect(sorted[1].id).toBe("A");
    });

    it("breaks CVSS ties by most recent first_seen", () => {
      const same = [
        { id: "X", severity: { source: "cvss", value: "7.5" }, first_seen: "2026-01-01" },
        { id: "Y", severity: { source: "cvss", value: "7.5" }, first_seen: "2026-06-01" },
      ];
      const sorted = sortIncidents(same, "severity");
      expect(sorted[0].id).toBe("Y");
      expect(sorted[1].id).toBe("X");
    });
  });

  describe("patch-lag mode", () => {
    it("sorts longest lag first", () => {
      const sorted = sortIncidents(fixture.incidents, "patch-lag");
      // INC-0001: 755 days, INC-0004: 109 days, INC-0006: 102 days, etc.
      expect(sorted[0].id).toBe("INC-0001");
    });
  });
});

// ── filterIncidents tests ─────────────────────────────────────────

describe("filterIncidents", () => {
  it("returns all incidents when no filters active", () => {
    const result = filterIncidents(fixture.incidents, {});
    expect(result).toHaveLength(6);
  });

  it("filters by single robot class", () => {
    const result = filterIncidents(fixture.incidents, { robot_classes: ["quadruped"] });
    expect(result).toHaveLength(2);
    result.forEach((i) => expect(i.robot_class).toBe("quadruped"));
  });

  it("filters by multiple robot classes (OR within group)", () => {
    const result = filterIncidents(fixture.incidents, { robot_classes: ["humanoid", "consumer"] });
    expect(result).toHaveLength(4); // humanoid: 0003,0005 · consumer: 0002,0006
  });

  it("filters by single status", () => {
    const result = filterIncidents(fixture.incidents, { statuses: ["unpatched"] });
    expect(result).toHaveLength(2); // unpatched: INC-0001, INC-0005
    result.forEach((i) => expect(i.status.state).toBe("unpatched"));
  });

  it("filters by multiple statuses (OR within group)", () => {
    const result = filterIncidents(fixture.incidents, { statuses: ["patched", "resolved"] });
    expect(result).toHaveLength(2);
  });

  it("filters by vendor", () => {
    const result = filterIncidents(fixture.incidents, { vendors: ["Vendor A"] });
    expect(result).toHaveLength(2);
    result.forEach((i) => expect(i.vendor).toBe("Vendor A"));
  });

  it("composes AND across groups", () => {
    const result = filterIncidents(fixture.incidents, {
      robot_classes: ["quadruped"],
      statuses: ["unpatched"],
    });
    expect(result).toHaveLength(1); // quadruped AND unpatched → INC-0001 only
    result.forEach((i) => {
      expect(i.robot_class).toBe("quadruped");
      expect(i.status.state).toBe("unpatched");
    });
  });

  it("composes AND across three groups", () => {
    const result = filterIncidents(fixture.incidents, {
      robot_classes: ["quadruped"],
      statuses: ["unpatched"],
      vendors: ["Vendor A"],
    });
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("INC-0001");
  });

  it("returns empty when filter combo matches nothing", () => {
    const result = filterIncidents(fixture.incidents, {
      robot_classes: ["humanoid"],
      vendors: ["Unitree"],
    });
    expect(result).toHaveLength(0);
  });
});

// ── searchIncidents tests ─────────────────────────────────────────

describe("searchIncidents", () => {
  const itemMap = buildItemMap(fixture.items);

  it("returns all when query is empty", () => {
    expect(searchIncidents(fixture.incidents, "", itemMap)).toHaveLength(6);
  });

  it("returns all when query is whitespace", () => {
    expect(searchIncidents(fixture.incidents, "   ", itemMap)).toHaveLength(6);
  });

  it("matches by title substring", () => {
    const result = searchIncidents(fixture.incidents, "lidar", itemMap);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("INC-0005");
  });

  it("matches by vendor substring", () => {
    const result = searchIncidents(fixture.incidents, "Unitree", itemMap);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("INC-0004");
  });

  it("matches by ai_summary substring", () => {
    const result = searchIncidents(fixture.incidents, "Bluetooth", itemMap);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("INC-0001");
  });

  it("matches by item title substring", () => {
    const result = searchIncidents(fixture.incidents, "expo", itemMap);
    expect(result).toHaveLength(1);
    expect(result[0].id).toBe("INC-0003");
  });

  it("is case-insensitive", () => {
    const lower = searchIncidents(fixture.incidents, "vendor a", itemMap);
    const upper = searchIncidents(fixture.incidents, "VENDOR A", itemMap);
    expect(lower).toHaveLength(upper.length);
    expect(lower.length).toBeGreaterThanOrEqual(1);
  });

  it("matches partial substrings", () => {
    const result = searchIncidents(fixture.incidents, "cam", itemMap);
    expect(result.length).toBeGreaterThanOrEqual(1);
  });
});
