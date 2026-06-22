import { templates } from "./templates";

export const profiles = ["generic", "strict", "static"] as const;
export type SafeBuildProfile = (typeof profiles)[number];

export interface TemplateFile {
  path: string;
  content: string;
  profiles: readonly SafeBuildProfile[];
}

export function templatesForProfile(profile: SafeBuildProfile): TemplateFile[] {
  return templates.filter((template) => template.profiles.includes(profile));
}

export function parseProfile(value: string): SafeBuildProfile {
  if (profiles.includes(value as SafeBuildProfile)) {
    return value as SafeBuildProfile;
  }
  throw new Error(`Unknown profile "${value}". Use one of: ${profiles.join(", ")}.`);
}
