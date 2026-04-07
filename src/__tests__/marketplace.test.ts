import { describe, it, expect } from "vitest";
import { existsSync } from "fs";
import { join } from "path";
import {
  ROOT,
  PLUGINS_DIR,
  MARKETPLACE_PATH,
  readJson,
  type Marketplace,
  type PluginJson,
} from "./helpers/fs-helpers.js";

const marketplace = readJson<Marketplace>(MARKETPLACE_PATH);

describe("marketplace.json", () => {
  it("필수 필드가 존재해야 한다", () => {
    expect(marketplace.name).toBeDefined();
    expect(marketplace.owner).toBeDefined();
    expect(marketplace.owner.name).toBeDefined();
    expect(marketplace.plugins).toBeDefined();
    expect(Array.isArray(marketplace.plugins)).toBe(true);
  });

  it("plugins 배열의 각 항목은 객체여야 한다", () => {
    for (const plugin of marketplace.plugins) {
      expect(typeof plugin).toBe("object");
      expect(plugin.name).toBeDefined();
      expect(plugin.source).toBeDefined();
    }
  });

  describe("로컬 플러그인", () => {
    const localPlugins = marketplace.plugins.filter(
      (p) => typeof p.source === "string"
    );

    it.each(localPlugins.map((p) => [p.name, p]))(
      "%s - source 디렉토리가 존재해야 한다",
      (_name, plugin) => {
        const sourcePath = join(ROOT, plugin.source as string);
        expect(existsSync(sourcePath)).toBe(true);
      }
    );

    it.each(localPlugins.map((p) => [p.name, p]))(
      "%s - plugin.json이 존재하고 name이 일치해야 한다",
      (_name, plugin) => {
        const pluginJsonPath = join(
          ROOT,
          plugin.source as string,
          ".claude-plugin/plugin.json"
        );
        expect(existsSync(pluginJsonPath)).toBe(true);

        const pluginJson = readJson<PluginJson>(pluginJsonPath);
        expect(pluginJson.name).toBe(plugin.name);
      }
    );
  });

  describe("외부 플러그인", () => {
    const externalPlugins = marketplace.plugins.filter(
      (p) => typeof p.source === "object"
    );

    it.each(
      externalPlugins.length > 0
        ? externalPlugins.map((p) => [p.name, p])
        : [["(없음)", null]]
    )("%s - source 객체에 source 필드가 있어야 한다", (_name, plugin) => {
      if (!plugin) return; // skip if no external plugins
      const source = plugin.source as { source: string };
      expect(["npm", "github"].includes(source.source)).toBe(true);
    });
  });
});
