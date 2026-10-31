import type { KeyMeta } from './storage/types.js';

export type RotationState = 'ok' | 'due-soon' | 'overdue';

export interface RotationStatus {
  id: string; provider: string; label: string;
  ageDays: number; dueInDays: number; state: RotationState; rotateUrl?: string;
}

// Provider dashboards where keys are rotated (may redirect).
export const ROTATE_URLS: Record<string, string> = {
  openai: 'https://platform.openai.com/api-keys',
  anthropic: 'https://console.anthropic.com/settings/keys',
};

const DAY = 86_400_000;

export function rotationStatus(meta: KeyMeta, now = new Date(), warnDays = 14): RotationStatus {
  const age = Math.floor((now.getTime() - new Date(meta.createdAt).getTime()) / DAY);
  const due = meta.rotateAfterDays - age;
  const state: RotationState = due < 0 ? 'overdue' : due <= warnDays ? 'due-soon' : 'ok';
  return { id: meta.id, provider: meta.provider, label: meta.label, ageDays: age, dueInDays: due, state, rotateUrl: ROTATE_URLS[meta.provider] };
}
