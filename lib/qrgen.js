// lib/qrgen.js — minimal dependency-free QR code generator
// SPDX-License-Identifier: GPL-3.0-only
// Compact implementation supporting L/M/Q/H error correction, byte mode, up to ~500 bytes.
(function (global) {
  "use strict";

  // Galois field tables for RS
  const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
  (function () {
    let x = 1;
    for (let i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  })();
  function gfMul(a, b) { if (a === 0 || b === 0) return 0; return EXP[LOG[a] + LOG[b]]; }

  // Generator polynomials cache
  const genPolyCache = {};
  function genPoly(degree) {
    if (genPolyCache[degree]) return genPolyCache[degree];
    let poly = [1];
    for (let i = 0; i < degree; i++) {
      const next = new Array(poly.length + 1).fill(0);
      for (let j = 0; j < poly.length; j++) {
        next[j] ^= poly[j];
        next[j + 1] ^= gfMul(poly[j], EXP[i]);
      }
      poly = next;
    }
    genPolyCache[degree] = poly;
    return poly;
  }

  function rsEncode(data, ecLen) {
    const gen = genPoly(ecLen);
    const buf = new Array(data.length + ecLen).fill(0);
    for (let i = 0; i < data.length; i++) buf[i] = data[i];
    for (let i = 0; i < data.length; i++) {
      const coef = buf[i];
      if (coef === 0) continue;
      for (let j = 0; j < gen.length; j++) buf[i + j] ^= gfMul(gen[j], coef);
    }
    return buf.slice(data.length);
  }

  // Capacity table: for each version 1..40, [bytes-L, bytes-M, bytes-Q, bytes-H]
  // We only need a subset; using conservative values for byte mode.
  const CAP = [
    [17,14,11,7],[32,26,20,14],[53,42,32,24],[78,62,46,34],[106,84,60,44],
    [134,106,74,58],[154,122,86,64],[192,152,108,84],[230,180,78,92],[271,213,99,103],
    [321,251,119,122],[367,287,137,127],[425,331,155,137],[458,365,177,151],[520,401,198,167]
  ];

  // EC codewords per block & block counts per version+level (L,M,Q,H) for v1..15
  // [ecPerBlock, group1Blocks, group1Data, group2Blocks, group2Data]
  const EC_TABLE = {
    L: [[7,1,19,0,0],[10,1,34,0,0],[15,1,55,0,0],[20,1,80,0,0],[26,1,108,0,0],
        [18,2,68,0,0],[20,2,78,0,0],[24,2,97,0,0],[30,2,116,0,0],[18,2,68,2,69],
        [20,4,81,0,0],[24,2,92,2,93],[26,4,107,0,0],[30,3,115,1,116],[22,5,87,1,88]],
    M: [[10,1,16,0,0],[16,1,28,0,0],[26,1,44,0,0],[18,2,32,0,0],[24,2,43,0,0],
        [16,4,27,0,0],[18,4,31,0,0],[22,2,38,2,39],[22,3,36,2,37],[26,4,43,1,44],
        [30,6,19,2,20],[28,6,22,2,23],[30,8,20,4,21],[30,8,20,4,21],[28,10,18,4,19]],
    Q: [[13,1,13,0,0],[22,1,26,0,0],[18,2,20,0,0],[26,2,18,0,0],[18,2,24,0,0],
        [24,4,22,0,0],[18,2,18,4,19],[22,3,16,4,17],[26,4,20,4,21],[24,5,18,4,19],
        [28,5,20,4,21],[30,7,18,4,19],[28,6,19,4,20],[30,8,19,4,20],[30,8,19,5,20]],
    H: [[17,1,9,0,0],[28,1,17,0,0],[22,2,13,0,0],[16,4,9,0,0],[22,4,15,0,0],
        [22,4,15,0,0],[20,4,16,4,17],[24,5,12,4,13],[24,5,14,4,15],[26,6,14,4,15],
        [28,8,12,4,13],[30,8,12,5,13],[30,8,12,6,13],[30,8,12,6,13],[28,10,12,6,13]]
  };

  function pickVersion(byteLen, level) {
    const lvl = CAP.map(c => c["LMQH".indexOf(level)]);
    for (let v = 0; v < CAP.length; v++) {
      if (CAP[v]["LMQH".indexOf(level)] >= byteLen) return v + 1;
    }
    return -1;
  }

  function buildMatrix(version, level, dataStr) {
    const size = version * 4 + 17;
    const m = Array.from({ length: size }, () => new Array(size).fill(null));

    // Finder patterns
    const placeFinder = (r, c) => {
      for (let i = -1; i <= 7; i++) for (let j = -1; j <= 7; j++) {
        const rr = r + i, cc = c + j;
        if (rr < 0 || cc < 0 || rr >= size || cc >= size) continue;
        const dark = (i >= 0 && i <= 6 && j >= 0 && j <= 6) && (i === 0 || i === 6 || j === 0 || j === 6 || (i >= 2 && i <= 4 && j >= 2 && j <= 4));
        m[rr][cc] = dark ? 1 : 0;
      }
    };
    placeFinder(0, 0); placeFinder(0, size - 7); placeFinder(size - 7, 0);

    // Timing patterns
    for (let i = 8; i < size - 8; i++) {
      if (m[6][i] === null) m[6][i] = (i % 2 === 0) ? 1 : 0;
      if (m[i][6] === null) m[i][6] = (i % 2 === 0) ? 1 : 0;
    }
    // Dark module
    m[size - 8][8] = 1;
    // Reserve format areas (set to 0, filled later)
    for (let i = 0; i < 9; i++) { if (m[8][i] === null) m[8][i] = 0; if (m[i][8] === null) m[i][8] = 0; }
    for (let i = 0; i < 8; i++) { m[8][size - 1 - i] = 0; m[size - 1 - i][8] = 0; }

    // Alignment patterns (v2+)
    const alignPos = alignmentPositions(version);
    for (const r of alignPos) for (const c of alignPos) {
      if (m[r][c] !== null) continue;
      for (let i = -2; i <= 2; i++) for (let j = -2; j <= 2; j++) {
        m[r + i][c + j] = (i === -2 || i === 2 || j === -2 || j === 2 || (i === 0 && j === 0)) ? 1 : 0;
      }
    }

    // Encode data
    const bytes = encodeUtf8(dataStr);
    const version1 = pickVersion(bytes.length, level);
    if (version1 < 1 || version1 > 15) throw new Error("QR: data too large (max v15 supported)");
    const v = version1;
    const ecInfo = EC_TABLE[level][v - 1];
    const totalDataCodewords = ecInfo[1] * ecInfo[2] + ecInfo[3] * ecInfo[4];

    // Bit stream: mode(4)=0100, char-count(8 for v1-9, 16 for v10-15), data, terminator, pad
    const bits = [];
    const pushBits = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1); };
    pushBits(0b0100, 4);
    const ccBits = v < 10 ? 8 : 16;
    pushBits(bytes.length, ccBits);
    for (const b of bytes) pushBits(b, 8);
    // terminator
    const rem = totalDataCodewords * 8 - bits.length;
    pushBits(0, Math.min(4, rem));
    // align to byte
    while (bits.length % 8 !== 0) bits.push(0);
    // pad bytes
    const pad = [0xEC, 0x11];
    let pi = 0;
    while (bits.length < totalDataCodewords * 8) { pushBits(pad[pi % 2], 8); pi++; }
    // to bytes
    const dataCodewords = [];
    for (let i = 0; i < bits.length; i += 8) {
      let b = 0; for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
      dataCodewords.push(b);
    }
    // split into blocks
    const blocks = [];
    let idx = 0;
    for (let g = 0; g < ecInfo[1]; g++) { blocks.push(dataCodewords.slice(idx, idx + ecInfo[2])); idx += ecInfo[2]; }
    for (let g = 0; g < ecInfo[3]; g++) { blocks.push(dataCodewords.slice(idx, idx + ecInfo[4])); idx += ecInfo[4]; }
    // EC per block
    const ecBlocks = blocks.map(b => rsEncode(b, ecInfo[0]));
    // interleave
    const finalData = [];
    const maxData = Math.max(ecInfo[2], ecInfo[4]);
    for (let i = 0; i < maxData; i++) for (const b of blocks) if (i < b.length) finalData.push(b[i]);
    for (let i = 0; i < ecInfo[0]; i++) for (const b of ecBlocks) if (i < b.length) finalData.push(b[i]);

    // Place data in zigzag
    let bitIdx = 0;
    const getBit = () => {
      if (bitIdx >= finalData.length * 8) return 0;
      const byte = finalData[Math.floor(bitIdx / 8)];
      const bit = (byte >> (7 - (bitIdx % 8))) & 1;
      bitIdx++;
      return bit;
    };
    let upward = true;
    let col = size - 1;
    while (col > 0) {
      if (col === 6) col--;
      for (let i = 0; i < size; i++) {
        const r = upward ? i : size - 1 - i;
        for (let c = 0; c < 2; c++) {
          const cc = col - c;
          if (m[r][cc] === null) m[r][cc] = getBit();
        }
      }
      col -= 2;
      upward = !upward;
    }

    // Apply mask (use mask 0 as a simple choice; compute penalty and pick best of 8 in a real impl)
    let bestMask = 0, bestPenalty = Infinity;
    const fmtInfo = formatInfoBits(level, 0);
    for (let mask = 0; mask < 8; mask++) {
      const trial = applyMask(m, mask, size);
      const penalty = calcPenalty(trial, size);
      if (penalty < bestPenalty) { bestPenalty = penalty; bestMask = mask; }
    }
    const masked = applyMask(m, bestMask, size);
    // place format info with best mask
    placeFormatInfo(masked, level, bestMask, size);

    return masked;
  }

  function alignmentPositions(version) {
    if (version < 2) return [];
    const numAlign = Math.floor(version / 7) + 2;
    const first = 6;
    const last = version * 4 + 10; // size - 7
    const step = (last - first) / (numAlign - 1);
    const pos = [first];
    for (let i = 1; i < numAlign - 1; i++) pos.push(Math.round(first + i * step));
    pos.push(last);
    return pos;
  }

  function applyMask(m, mask, size) {
    const copy = m.map(row => row.slice());
    for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) {
      if (isReserved(r, c, size)) continue;
      if (maskCondition(mask, r, c)) copy[r][c] ^= 1;
    }
    return copy;
  }
  function isReserved(r, c, size) {
    // finder + separators + timing + format + dark
    if (r < 9 && c < 9) return true;
    if (r < 9 && c >= size - 8) return true;
    if (r >= size - 8 && c < 9) return true;
    if (r === 6 || c === 6) return true;
    return false;
  }
  function maskCondition(mask, r, c) {
    switch (mask) {
      case 0: return (r + c) % 2 === 0;
      case 1: return r % 2 === 0;
      case 2: return c % 3 === 0;
      case 3: return (r + c) % 3 === 0;
      case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
      case 5: return (r * c) % 2 + (r * c) % 3 === 0;
      case 6: return ((r * c) % 2 + (r * c) % 3) % 2 === 0;
      case 7: return ((r + c) % 2 + (r * c) % 3) % 2 === 0;
    }
    return false;
  }
  function calcPenalty(m, size) {
    let p = 0;
    // rule 1
    for (let r = 0; r < size; r++) {
      let run = 1;
      for (let c = 1; c < size; c++) {
        if (m[r][c] === m[r][c - 1]) run++;
        else { if (run >= 5) p += 3 + (run - 5); run = 1; }
      }
      if (run >= 5) p += 3 + (run - 5);
    }
    for (let c = 0; c < size; c++) {
      let run = 1;
      for (let r = 1; r < size; r++) {
        if (m[r][c] === m[r - 1][c]) run++;
        else { if (run >= 5) p += 3 + (run - 5); run = 1; }
      }
      if (run >= 5) p += 3 + (run - 5);
    }
    return p;
  }

  function formatInfoBits(level, mask) {
    const lvl = { L: 1, M: 0, Q: 3, H: 2 }[level];
    const data = (lvl << 3) | mask;
    let bch = data;
    for (let i = 0; i < 10; i++) if (bch & (1 << (10 - i))) bch ^= 0b10100110111 << (10 - 1 - i);
    bch = (data << 10) | (bch & 0x3ff);
    return bch ^ 0b101010000010010;
  }
  function placeFormatInfo(m, level, mask, size) {
    const fmt = formatInfoBits(level, mask);
    // around top-left
    for (let i = 0; i < 15; i++) {
      const bit = (fmt >> i) & 1;
      // top-left
      if (i < 6) m[8][i] = bit;
      else if (i === 6) m[8][7] = bit;
      else if (i === 7) m[8][8] = bit;
      else if (i === 8) m[7][8] = bit;
      else m[14 - i][8] = bit;
      // top-right + bottom-left
      if (i < 8) m[8][size - 1 - i] = bit;
      else m[size - 15 + i][8] = bit;
    }
    m[size - 8][8] = 1; // dark module
  }

  function encodeUtf8(s) {
    const out = [];
    for (let i = 0; i < s.length; i++) {
      let c = s.charCodeAt(i);
      if (c < 0x80) out.push(c);
      else if (c < 0x800) { out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f)); }
      else { out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f)); }
    }
    return out;
  }

  function renderToCanvas(matrix, scale, canvas) {
    const size = matrix.length;
    const quiet = 4;
    const total = (size + quiet * 2) * scale;
    canvas.width = total; canvas.height = total;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#fff"; ctx.fillRect(0, 0, total, total);
    ctx.fillStyle = "#000";
    for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) {
      if (matrix[r][c]) ctx.fillRect((c + quiet) * scale, (r + quiet) * scale, scale, scale);
    }
    return canvas;
  }

  function generate(text, level, scale, canvas) {
    level = level || "M";
    scale = scale || 6;
    canvas = canvas || document.createElement("canvas");
    const bytes = encodeUtf8(text);
    const version = pickVersion(bytes.length, level);
    if (version < 1 || version > 15) throw new Error("QR: data too large (max v15 supported)");
    const m = buildMatrix(version, level, text);
    return renderToCanvas(m, scale, canvas);
  }

  global.TarnQR = { generate };
})(typeof self !== "undefined" ? self : this);
