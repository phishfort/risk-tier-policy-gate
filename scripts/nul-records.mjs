export function splitNul(buffer) {
  if (!Buffer.isBuffer(buffer)) throw new TypeError('NUL record input must be a Buffer');
  const records = [];
  let start = 0;
  for (let index = 0; index < buffer.length; index += 1) {
    if (buffer[index] === 0) {
      if (index > start) records.push(buffer.subarray(start, index));
      start = index + 1;
    }
  }
  if (start < buffer.length) records.push(buffer.subarray(start));
  return records;
}

export function pathSetFromNul(buffer) {
  return new Set(splitNul(buffer).map(file => file.toString('hex')));
}
