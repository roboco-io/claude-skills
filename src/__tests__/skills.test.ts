import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "fs";
import { join, dirname } from "path";
import {
  findAllSkills,
  parseSkillFrontmatter,
  extractMarkdownLinks,
} from "./helpers/fs-helpers.js";

const allSkills = findAllSkills();

describe("SKILL.md", () => {
  it("스킬이 1개 이상 존재해야 한다", () => {
    expect(allSkills.length).toBeGreaterThan(0);
  });

  describe.each(allSkills.map((s) => [`${s.category}/${s.skill}`, s]))(
    "%s",
    (_label, skill) => {
      it("YAML frontmatter가 존재해야 한다", () => {
        const content = readFileSync(skill.path, "utf-8");
        expect(content).toMatch(/^---\n[\s\S]*?\n---/);
      });

      it("name 필드가 존재하고 비어있지 않아야 한다", () => {
        const fm = parseSkillFrontmatter(skill.path);
        expect(fm.name).toBeDefined();
        expect(fm.name.trim().length).toBeGreaterThan(0);
      });

      it("description 필드가 존재하고 비어있지 않아야 한다", () => {
        const fm = parseSkillFrontmatter(skill.path);
        expect(fm.description).toBeDefined();
        expect(fm.description.trim().length).toBeGreaterThan(0);
      });

      it("SKILL.md 본문(frontmatter 이후)이 비어있지 않아야 한다", () => {
        const content = readFileSync(skill.path, "utf-8");
        const body = content.replace(/^---\n[\s\S]*?\n---\n*/, "").trim();
        expect(body.length).toBeGreaterThan(0);
      });

      it("references/ 링크가 있다면 해당 파일이 존재해야 한다", () => {
        const content = readFileSync(skill.path, "utf-8");
        const links = extractMarkdownLinks(content);
        const refLinks = links.filter(
          (l) => l.startsWith("references/") || l.startsWith("./references/")
        );

        for (const link of refLinks) {
          const refPath = join(dirname(skill.path), link);
          expect(
            existsSync(refPath),
            `참조 파일 누락: ${link} (in ${skill.path})`
          ).toBe(true);
        }
      });

      it("500줄을 초과하지 않아야 한다 (Progressive Disclosure 가이드라인)", () => {
        const content = readFileSync(skill.path, "utf-8");
        const lineCount = content.split("\n").length;
        expect(
          lineCount,
          `${skill.path}: ${lineCount}줄 (최대 500줄)`
        ).toBeLessThanOrEqual(500);
      });
    }
  );
});
