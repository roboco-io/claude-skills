import { readFileSync, existsSync, readdirSync } from "fs";
import { join, resolve } from "path";
import { parse as parseYaml } from "yaml";

export const ROOT = resolve(import.meta.dirname, "../../../");
export const PLUGINS_DIR = join(ROOT, "plugins");
export const MARKETPLACE_PATH = join(ROOT, ".claude-plugin/marketplace.json");

export interface SkillFrontmatter {
  name: string;
  description: string;
  [key: string]: unknown;
}

export interface PluginJson {
  name: string;
  description: string;
  version: string;
  category: string;
}

export interface MarketplacePlugin {
  name: string;
  source: string | { source: string; [key: string]: unknown };
  version?: string;
  category?: string;
  skills?: string[];
}

export interface Marketplace {
  name: string;
  owner: { name: string; [key: string]: unknown };
  plugins: MarketplacePlugin[];
}

export function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf-8")) as T;
}

export function parseSkillFrontmatter(skillMdPath: string): SkillFrontmatter {
  const content = readFileSync(skillMdPath, "utf-8");
  const match = content.match(/^---\n([\s\S]*?)\n---/);
  if (!match) throw new Error(`No frontmatter found in ${skillMdPath}`);
  return parseYaml(match[1]) as SkillFrontmatter;
}

export function findAllSkills(): { category: string; skill: string; path: string }[] {
  const skills: { category: string; skill: string; path: string }[] = [];
  if (!existsSync(PLUGINS_DIR)) return skills;

  for (const category of readdirSync(PLUGINS_DIR, { withFileTypes: true })) {
    if (!category.isDirectory()) continue;
    const skillsDir = join(PLUGINS_DIR, category.name, "skills");
    if (!existsSync(skillsDir)) continue;

    for (const skill of readdirSync(skillsDir, { withFileTypes: true })) {
      if (!skill.isDirectory()) continue;
      const skillMd = join(skillsDir, skill.name, "SKILL.md");
      if (existsSync(skillMd)) {
        skills.push({ category: category.name, skill: skill.name, path: skillMd });
      }
    }
  }
  return skills;
}

export function extractMarkdownLinks(content: string): string[] {
  const linkRegex = /\[([^\]]*)\]\(([^)]+)\)/g;
  const links: string[] = [];
  let match;
  while ((match = linkRegex.exec(content)) !== null) {
    links.push(match[2]);
  }
  return links;
}
