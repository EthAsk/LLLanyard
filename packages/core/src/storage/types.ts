export interface KeyMeta {
  id: string; // "openai:default"
  provider: string;
  label: string; // also the "client" in freelancer/agency mode
  createdAt: string; // ISO date; reset on rotation
  rotateAfterDays: number;
  last4: string;
  envName?: string; // the environment variable this key is given to tools as (e.g. GITHUB_TOKEN)
}

export interface SetOptions {
  label?: string;
  rotateAfterDays?: number;
  envName?: string;
}

export interface SecureStore {
  set(provider: string, secret: string, opts?: SetOptions): KeyMeta;
  get(provider: string, label?: string): string | null;
  list(): KeyMeta[]; // never returns secrets
  remove(provider: string, label?: string): boolean;
}
