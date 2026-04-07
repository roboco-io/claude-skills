import { describe, it, expect } from "vitest";
import { existsSync } from "fs";
import { join } from "path";
import {
  ROOT,
  MARKETPLACE_PATH,
  PLUGINS_DIR,
  readJson,
  findAllSkills,
  parseSkillFrontmatter,
  type Marketplace,
} from "./helpers/fs-helpers.js";

const marketplace = readJson<Marketplace>(MARKETPLACE_PATH);
const allSkills = findAllSkills();

describe("프로젝트 무결성", () => {
  describe("marketplace ↔ 파일시스템 동기화", () => {
    const localPlugins = marketplace.plugins.filter(
      (p) => typeof p.source === "string"
    );

    it.each(localPlugins.map((p) => [p.name, p]))(
      "%s - marketplace에 등록된 플러그인 디렉토리가 존재해야 한다",
      (_name, plugin) => {
        const dir = join(ROOT, plugin.source as string);
        expect(existsSync(dir)).toBe(true);
      }
    );

    it("파일시스템의 모든 카테고리가 marketplace에 등록되어 있어야 한다", () => {
      const fsCategories = new Set(allSkills.map((s) => s.category));
      const mpNames = new Set(
        localPlugins.map((p) => p.name)
      );

      for (const cat of fsCategories) {
        expect(
          mpNames.has(cat),
          `카테고리 '${cat}'가 marketplace.json에 등록되지 않음`
        ).toBe(true);
      }
    });
  });

  describe("스킬 이름 고유성", () => {
    it("모든 스킬의 name이 고유해야 한다", () => {
      const names = allSkills.map((s) => parseSkillFrontmatter(s.path).name);
      const duplicates = names.filter(
        (name, i) => names.indexOf(name) !== i
      );
      expect(duplicates, `중복된 스킬 이름: ${duplicates.join(", ")}`).toEqual(
        []
      );
    });
  });

  describe("aws-well-architected 오케스트레이터", () => {
    const waPillars = [
      "aws-wa-security",
      "aws-wa-reliability",
      "aws-wa-performance",
      "aws-wa-cost",
      "aws-wa-sustainability",
      "aws-wa-operational-excellence",
    ];

    it.each(waPillars)("%s - 하위 스킬이 존재해야 한다", (pillar) => {
      const found = allSkills.some((s) => s.skill === pillar);
      expect(found, `하위 스킬 누락: ${pillar}`).toBe(true);
    });

    it("오케스트레이터 스킬(aws-well-architected)이 존재해야 한다", () => {
      const found = allSkills.some((s) => s.skill === "aws-well-architected");
      expect(found).toBe(true);
    });
  });

  describe("필수 파일 존재", () => {
    const requiredFiles = [
      ".claude-plugin/marketplace.json",
      "CLAUDE.md",
      "README.md",
    ];

    it.each(requiredFiles)("%s 파일이 존재해야 한다", (file) => {
      expect(existsSync(join(ROOT, file))).toBe(true);
    });
  });
});
