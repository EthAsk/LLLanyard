/**
 * The agent's own explanation of why it wants to run something, shown in the confirmation window. It is untrusted text:
 * it is flattened to one short line, so it can't pose as the script, command or key lines underneath it.
 */
export const REASON_MAX = 300;

export function cleanReason(reason: unknown): string {
  if (typeof reason !== 'string') return '';
  // Control, formatting (including right-to-left overrides) and line separator characters become spaces.
  const flat = reason.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\s]+/gu, ' ').trim();
  return flat.length > REASON_MAX ? `${flat.slice(0, REASON_MAX - 1)}…` : flat;
}
