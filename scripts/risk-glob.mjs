export function toRegex(glob) {
  let source = '^';
  for (let index = 0; index < glob.length; index += 1) {
    const char = glob[index];
    if (char === '*' && glob[index + 1] === '*') {
      if (glob[index + 2] === '/') {
        source += '([\\s\\S]*/)?';
        index += 2;
      } else {
        source += '[\\s\\S]*';
        index += 1;
      }
    } else if (char === '*') {
      source += '[^/]*';
    } else if (char === '?') {
      source += '[^/]';
    } else {
      source += '\\^$.*+?()[]{}|'.includes(char) ? `\\${char}` : char;
    }
  }
  return new RegExp(`${source}$`);
}
