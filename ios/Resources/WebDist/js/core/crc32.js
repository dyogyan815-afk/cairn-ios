const TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export class Crc32 {
  constructor() { this.c = 0xffffffff; }
  update(u8) {
    let c = this.c;
    for (let i = 0; i < u8.length; i++) c = TABLE[(c ^ u8[i]) & 0xff] ^ (c >>> 8);
    this.c = c;
    return this;
  }
  get value() { return (this.c ^ 0xffffffff) >>> 0; }
}

export function crc32(u8) { return new Crc32().update(u8).value; }
