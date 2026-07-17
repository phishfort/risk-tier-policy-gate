export function toRegex(glob) {
  const escaped = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*\//g, '::DOUBLE_STAR_SLASH::')
    .replace(/\*\*/g, '::DOUBLE_STAR::')
    .replace(/\*/g, '[^/]*')
    .replace(/::DOUBLE_STAR_SLASH::/g, '([\\s\\S]*/)?')
    .replace(/::DOUBLE_STAR::/g, '[\\s\\S]*');
  return new RegExp(`^${escaped}$`);
}
