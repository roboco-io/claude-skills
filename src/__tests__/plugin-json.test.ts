import { describe, it, expect } from "vitest";
import { existsSync, readdirSync } from "fs";
import { join } from "path";
import { PLUGINS_DIR, readJson, type PluginJson } from "./helpers/fs-helpers.js";

const categories = readdirSync(PLUGINS_DIR, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name);

describe("plugin.json", () => {
  it.each(categories)("%s - plugin.json이 존재해야 한다", (category) => {
    const path = join(PLUGINS_DIR, category, ".claude-plugin/plugin.json");
    expect(existsSync(path)).toBe(true);
  });

  it.each(categories)(
    "%s - 필수 필드(name, description, version, category)가 존재해야 한다",
    (category) => {
      const path = join(PLUGINS_DIR, category, ".claude-plugin/plugin.json");
      const plugin = readJson<PluginJson>(path);

      expect(plugin.name).toBeDefined();
      expect(plugin.description).toBeDefined();
      expect(plugin.version).toBeDefined();
      expect(plugin.category).toBeDefined();
    }
  );

  it.each(categories)(
    "%s - name이 디렉토리명과 일치해야 한다",
    (category) => {
      const path = join(PLUGINS_DIR, category, ".claude-plugin/plugin.json");
      const plugin = readJson<PluginJson>(path);
      expect(plugin.name).toBe(category);
    }
  );

  it.each(categories)(
    "%s - version이 semver 형식이어야 한다",
    (category) => {
      const path = join(PLUGINS_DIR, category, ".claude-plugin/plugin.json");
      const plugin = readJson<PluginJson>(path);
      expect(plugin.version).toMatch(/^\d+\.\d+\.\d+/);
    }
  );
});
