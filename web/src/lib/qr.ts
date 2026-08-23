// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Serraniel and the Sendan contributors

/**
 * A QR code for a link, drawn here rather than fetched.
 *
 * The link contains the key. Sending it to a service that renders codes would
 * hand that service every file this instance sends, which is the one thing the
 * whole design exists to prevent - so no image service, and no library that
 * might reach for one.
 *
 * ## What is implemented, and what is not
 *
 * Byte mode only, error correction level M, versions 1 to 10. A link is mixed
 * case with punctuation, so the numeric and alphanumeric modes could never
 * apply to one; implementing them would be writing code no link can reach.
 * Level M recovers about 15% and is what a code printed on paper or shown on a
 * screen wants. Version 10 holds 213 bytes, which is far more than any link
 * this produces.
 *
 * ## How it is known to be right
 *
 * `qr.vectors.json` holds matrices produced by an independent implementation -
 * `qrencode`, forced into byte mode at level M - and `qr.test.ts` compares
 * module for module. An encoder nobody checks against another implementation is
 * an encoder that produces something plausible and unreadable.
 */

/** A square of modules. True is dark. */
export type Matrix = boolean[][];

/** Error correction level M: about 15% recoverable. */
const EC_LEVEL_M = 0;

/**
 * Per version: error correction codewords per block, then the block groups.
 *
 * Taken from the standard's tables for level M. Any error here shows up
 * immediately as a mismatch against the reference vectors, which is why they
 * are transcribed rather than derived.
 */
const VERSIONS: Array<{
  ecPerBlock: number;
  groups: Array<{ blocks: number; dataCodewords: number }>;
}> = [
  { ecPerBlock: 10, groups: [{ blocks: 1, dataCodewords: 16 }] },
  { ecPerBlock: 16, groups: [{ blocks: 1, dataCodewords: 28 }] },
  { ecPerBlock: 26, groups: [{ blocks: 1, dataCodewords: 44 }] },
  { ecPerBlock: 18, groups: [{ blocks: 2, dataCodewords: 32 }] },
  { ecPerBlock: 24, groups: [{ blocks: 2, dataCodewords: 43 }] },
  { ecPerBlock: 16, groups: [{ blocks: 4, dataCodewords: 27 }] },
  { ecPerBlock: 18, groups: [{ blocks: 4, dataCodewords: 31 }] },
  {
    ecPerBlock: 22,
    groups: [
      { blocks: 2, dataCodewords: 38 },
      { blocks: 2, dataCodewords: 39 },
    ],
  },
  {
    ecPerBlock: 22,
    groups: [
      { blocks: 3, dataCodewords: 36 },
      { blocks: 2, dataCodewords: 37 },
    ],
  },
  {
    ecPerBlock: 26,
    groups: [
      { blocks: 4, dataCodewords: 43 },
      { blocks: 1, dataCodewords: 44 },
    ],
  },
];

/** Where the alignment patterns sit, per version. */
const ALIGNMENT: number[][] = [
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
  [6, 28, 50],
];

/** Raised when a link is longer than this encoder will carry. */
export class TooMuchData extends Error {
  constructor(bytes: number) {
    super(`qr: ${bytes} bytes is more than version 10 holds at this level`);
    this.name = "TooMuchData";
  }
}

// --- GF(256), the field the error correction is computed in ---------------

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    // The primitive polynomial the standard fixes for QR.
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255] as number;
}

function multiply(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[(LOG[a] as number) + (LOG[b] as number)] as number;
}

/**
 * The generator polynomial for a given number of error correction codewords.
 *
 * Built by multiplying out (x - a^i), which produces coefficients in ascending
 * powers, then reversed: the division below indexes them in descending order
 * with the leading 1 first. Leaving them ascending produces error correction
 * bytes that are wrong but plausible - the code still scans, and decodes to
 * nothing. It took comparing against another implementation's bytes to see,
 * because a second implementation written from the same misunderstanding
 * agrees with the first.
 */
function generator(degree: number): number[] {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array<number>(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] = (next[j] as number) ^ multiply(poly[j] as number, EXP[i] as number);
      next[j + 1] = (next[j + 1] as number) ^ (poly[j] as number);
    }
    poly = next;
  }
  return poly.reverse();
}

/** The error correction codewords for one block. */
function errorCorrection(data: number[], count: number): number[] {
  const gen = generator(count);
  const remainder = new Array<number>(count).fill(0);

  for (const byte of data) {
    const factor = byte ^ (remainder[0] as number);
    remainder.shift();
    remainder.push(0);
    for (let i = 0; i < count; i++) {
      remainder[i] = (remainder[i] as number) ^ multiply(gen[i + 1] as number, factor);
    }
  }
  return remainder;
}

// --- Data ------------------------------------------------------------------

/** The smallest version that holds this many bytes. */
function versionFor(byteLength: number): number {
  for (let version = 1; version <= VERSIONS.length; version++) {
    const spec = VERSIONS[version - 1] as (typeof VERSIONS)[number];
    const capacity = spec.groups.reduce((sum, g) => sum + g.blocks * g.dataCodewords, 0);
    // Four bits for the mode, then the length: eight bits below version 10 and
    // sixteen from ten upwards, which is why the boundary is checked here
    // rather than assumed.
    const headerBits = 4 + (version < 10 ? 8 : 16);
    if (Math.ceil(headerBits / 8) + byteLength <= capacity) return version;
  }
  throw new TooMuchData(byteLength);
}

/** The data codewords, padded to the version's capacity. */
function dataCodewords(bytes: Uint8Array, version: number): number[] {
  const spec = VERSIONS[version - 1] as (typeof VERSIONS)[number];
  const capacity = spec.groups.reduce((sum, g) => sum + g.blocks * g.dataCodewords, 0);
  const lengthBits = version < 10 ? 8 : 16;

  const bits: number[] = [];
  const push = (value: number, width: number) => {
    for (let i = width - 1; i >= 0; i--) bits.push((value >> i) & 1);
  };

  push(0b0100, 4); // byte mode
  push(bytes.length, lengthBits);
  for (const byte of bytes) push(byte, 8);

  // A terminator of up to four zero bits, then zeros to the next whole byte.
  const room = capacity * 8 - bits.length;
  for (let i = 0; i < Math.min(4, room); i++) bits.push(0);
  while (bits.length % 8 !== 0) bits.push(0);

  const codewords: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | (bits[i + j] as number);
    codewords.push(byte);
  }

  // The two pad bytes the standard names, alternating and always beginning
  // with the first of them. Keyed on how many have been added rather than on
  // the total length: with an odd number of data codewords the latter starts
  // the sequence on the wrong one, which is a valid-looking code that decodes
  // to the wrong bytes.
  const pad = [0xec, 0x11];
  for (let i = 0; codewords.length < capacity; i++) codewords.push(pad[i % 2] as number);
  return codewords;
}

/**
 * The final codeword stream: blocks interleaved, then their error correction.
 *
 * Interleaving is what makes a burst of damage survivable - it spreads
 * neighbouring modules across different blocks, so no single block takes all of
 * it.
 */
function interleave(data: number[], version: number): number[] {
  const spec = VERSIONS[version - 1] as (typeof VERSIONS)[number];

  const blocks: number[][] = [];
  const ecBlocks: number[][] = [];
  let at = 0;
  for (const group of spec.groups) {
    for (let i = 0; i < group.blocks; i++) {
      const block = data.slice(at, at + group.dataCodewords);
      at += group.dataCodewords;
      blocks.push(block);
      ecBlocks.push(errorCorrection(block, spec.ecPerBlock));
    }
  }

  const out: number[] = [];
  const longest = Math.max(...blocks.map((b) => b.length));
  for (let i = 0; i < longest; i++) {
    for (const block of blocks) if (i < block.length) out.push(block[i] as number);
  }
  for (let i = 0; i < spec.ecPerBlock; i++) {
    for (const block of ecBlocks) out.push(block[i] as number);
  }
  return out;
}

// --- The matrix ------------------------------------------------------------

type Cell = { dark: boolean; reserved: boolean };

function blank(size: number): Cell[][] {
  return Array.from({ length: size }, () =>
    Array.from({ length: size }, () => ({ dark: false, reserved: false })),
  );
}

function place(grid: Cell[][], row: number, column: number, dark: boolean, reserved = true) {
  const cell = (grid[row] as Cell[])[column] as Cell;
  cell.dark = dark;
  cell.reserved = reserved;
}

function finder(grid: Cell[][], row: number, column: number) {
  for (let r = -1; r <= 7; r++) {
    for (let c = -1; c <= 7; c++) {
      const y = row + r;
      const x = column + c;
      if (y < 0 || x < 0 || y >= grid.length || x >= grid.length) continue;
      const outer = r >= 0 && r <= 6 && (c === 0 || c === 6);
      const side = c >= 0 && c <= 6 && (r === 0 || r === 6);
      const core = r >= 2 && r <= 4 && c >= 2 && c <= 4;
      place(grid, y, x, outer || side || core);
    }
  }
}

function alignment(grid: Cell[][], version: number) {
  const centres = ALIGNMENT[version - 1] as number[];
  for (const row of centres) {
    for (const column of centres) {
      // Not where a finder pattern already is.
      const nearFinder =
        (row <= 8 && column <= 8) ||
        (row <= 8 && column >= grid.length - 9) ||
        (row >= grid.length - 9 && column <= 8);
      if (nearFinder) continue;

      for (let r = -2; r <= 2; r++) {
        for (let c = -2; c <= 2; c++) {
          const edge = Math.abs(r) === 2 || Math.abs(c) === 2;
          place(grid, row + r, column + c, edge || (r === 0 && c === 0));
        }
      }
    }
  }
}

/** Format information: the level and mask, with its BCH check and mask. */
function formatBits(mask: number): number {
  const data = (EC_LEVEL_M << 3) | mask;
  let value = data << 10;
  for (let i = 14; i >= 10; i--) {
    if ((value >> i) & 1) value ^= 0b10100110111 << (i - 10);
  }
  return ((data << 10) | value) ^ 0b101010000010010;
}

/** Version information, for versions seven and above. */
function versionBits(version: number): number {
  let value = version << 12;
  for (let i = 17; i >= 12; i--) {
    if ((value >> i) & 1) value ^= 0b1111100100101 << (i - 12);
  }
  return (version << 12) | value;
}

function reserveFormat(grid: Cell[][], version: number) {
  const size = grid.length;
  for (let i = 0; i < 9; i++) {
    if (i !== 6) {
      place(grid, 8, i, false);
      place(grid, i, 8, false);
    }
  }
  for (let i = 0; i < 8; i++) {
    place(grid, 8, size - 1 - i, false);
    place(grid, size - 1 - i, 8, false);
  }
  // Always dark, and never data.
  place(grid, size - 8, 8, true);

  if (version >= 7) {
    for (let i = 0; i < 18; i++) {
      const row = Math.floor(i / 3);
      const column = size - 11 + (i % 3);
      place(grid, row, column, false);
      place(grid, column, row, false);
    }
  }
}

function writeFormat(grid: Cell[][], mask: number, version: number) {
  const size = grid.length;
  const bits = formatBits(mask);

  // The standard places bit 0 at (0,8) and works round to bit 14 at (8,0), and
  // the second copy in the opposite direction. Reversing that produces a code
  // whose format field decodes to a different mask - which is a code that
  // scans, and scans to nothing.
  const first: Array<[number, number]> = [
    [0, 8],
    [1, 8],
    [2, 8],
    [3, 8],
    [4, 8],
    [5, 8],
    [7, 8],
    [8, 8],
    [8, 7],
    [8, 5],
    [8, 4],
    [8, 3],
    [8, 2],
    [8, 1],
    [8, 0],
  ];
  const second: Array<[number, number]> = [
    [8, size - 1],
    [8, size - 2],
    [8, size - 3],
    [8, size - 4],
    [8, size - 5],
    [8, size - 6],
    [8, size - 7],
    [8, size - 8],
    [size - 7, 8],
    [size - 6, 8],
    [size - 5, 8],
    [size - 4, 8],
    [size - 3, 8],
    [size - 2, 8],
    [size - 1, 8],
  ];

  for (let i = 0; i < 15; i++) {
    const bit = ((bits >> i) & 1) === 1;
    const [ar, ac] = first[i] as [number, number];
    const [br, bc] = second[i] as [number, number];
    place(grid, ar, ac, bit);
    place(grid, br, bc, bit);
  }

  if (version >= 7) {
    const vbits = versionBits(version);
    for (let i = 0; i < 18; i++) {
      const bit = ((vbits >> i) & 1) === 1;
      const row = Math.floor(i / 3);
      const column = size - 11 + (i % 3);
      place(grid, row, column, bit);
      place(grid, column, row, bit);
    }
  }
}

/** Whether a module is flipped, for one of the eight masks. */
function masked(mask: number, row: number, column: number): boolean {
  switch (mask) {
    case 0:
      return (row + column) % 2 === 0;
    case 1:
      return row % 2 === 0;
    case 2:
      return column % 3 === 0;
    case 3:
      return (row + column) % 3 === 0;
    case 4:
      return (Math.floor(row / 2) + Math.floor(column / 3)) % 2 === 0;
    case 5:
      return ((row * column) % 2) + ((row * column) % 3) === 0;
    case 6:
      return (((row * column) % 2) + ((row * column) % 3)) % 2 === 0;
    default:
      return (((row + column) % 2) + ((row * column) % 3)) % 2 === 0;
  }
}

/**
 * How bad a masked matrix looks to a scanner.
 *
 * The four rules are the standard's. They exist to avoid patterns a decoder
 * would mistake for structure - most of all anything resembling a finder.
 */
function penalty(grid: Cell[][]): number {
  const size = grid.length;
  const dark = (r: number, c: number) => ((grid[r] as Cell[])[c] as Cell).dark;
  let score = 0;

  // Runs of five or more in a line.
  for (let i = 0; i < size; i++) {
    for (const horizontal of [true, false]) {
      let run = 1;
      for (let j = 1; j < size; j++) {
        const previous = horizontal ? dark(i, j - 1) : dark(j - 1, i);
        const current = horizontal ? dark(i, j) : dark(j, i);
        if (current === previous) {
          run++;
          if (run === 5) score += 3;
          else if (run > 5) score += 1;
        } else run = 1;
      }
    }
  }

  // Blocks of the same colour.
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const first = dark(r, c);
      if (first === dark(r, c + 1) && first === dark(r + 1, c) && first === dark(r + 1, c + 1)) {
        score += 3;
      }
    }
  }

  // Anything that looks like a finder pattern.
  const patterns = [
    [true, false, true, true, true, false, true, false, false, false, false],
    [false, false, false, false, true, false, true, true, true, false, true],
  ];
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      for (const pattern of patterns) {
        if (c + pattern.length <= size) {
          if (pattern.every((want, i) => dark(r, c + i) === want)) score += 40;
        }
        if (r + pattern.length <= size) {
          if (pattern.every((want, i) => dark(r + i, c) === want)) score += 40;
        }
      }
    }
  }

  // Too much of one colour overall.
  let darkCount = 0;
  for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) if (dark(r, c)) darkCount++;
  const percent = (darkCount * 100) / (size * size);
  score += Math.floor(Math.abs(percent - 50) / 5) * 10;

  return score;
}

function draw(codewords: number[], version: number, mask: number): Cell[][] {
  const size = version * 4 + 17;
  const grid = blank(size);

  finder(grid, 0, 0);
  finder(grid, 0, size - 7);
  finder(grid, size - 7, 0);
  alignment(grid, version);

  // Timing patterns.
  for (let i = 8; i < size - 8; i++) {
    place(grid, 6, i, i % 2 === 0);
    place(grid, i, 6, i % 2 === 0);
  }

  reserveFormat(grid, version);

  // The data, snaking upwards and downwards in pairs of columns.
  let bit = 0;
  let upward = true;
  for (let right = size - 1; right > 0; right -= 2) {
    if (right === 6) right--; // the timing column is skipped entirely
    for (let step = 0; step < size; step++) {
      const row = upward ? size - 1 - step : step;
      for (const column of [right, right - 1]) {
        const cell = (grid[row] as Cell[])[column] as Cell;
        if (cell.reserved) continue;

        const byte = codewords[bit >> 3] ?? 0;
        const value = ((byte >> (7 - (bit & 7))) & 1) === 1;
        cell.dark = value !== masked(mask, row, column);
        bit++;
      }
    }
    upward = !upward;
  }

  writeFormat(grid, mask, version);
  return grid;
}

/**
 * How many modules are left for data at a given version.
 *
 * Exported for the test that compares it against the standard's capacities.
 * Reserving one module too many or too few shifts every data bit after the
 * mistake, which produces a code that scans and decodes to nothing.
 */
export function dataModuleCount(version: number): number {
  const size = version * 4 + 17;
  const grid = blank(size);

  finder(grid, 0, 0);
  finder(grid, 0, size - 7);
  finder(grid, size - 7, 0);
  alignment(grid, version);
  for (let i = 8; i < size - 8; i++) {
    place(grid, 6, i, i % 2 === 0);
    place(grid, i, 6, i % 2 === 0);
  }
  reserveFormat(grid, version);

  return grid.flat().filter((cell) => !cell.reserved).length;
}

/**
 * A QR code with a chosen mask, for comparing against another implementation.
 *
 * Exported for the test that checks this encoder module for module: a mismatch
 * has two possible causes, the mask chosen and everything else, and being able
 * to fix the mask separates them. Nothing in the interface uses it.
 */
export function encodeWithMask(text: string, mask: number): Matrix {
  const bytes = new TextEncoder().encode(text);
  const version = versionFor(bytes.length);
  const codewords = interleave(dataCodewords(bytes, version), version);
  return draw(codewords, version, mask).map((row) => row.map((cell) => cell.dark));
}

/**
 * A QR code for the given text.
 *
 * The mask is chosen by scoring all eight, which is what the standard requires
 * and what makes the output match another implementation's module for module.
 */
export function encode(text: string): Matrix {
  const bytes = new TextEncoder().encode(text);
  const version = versionFor(bytes.length);
  const codewords = interleave(dataCodewords(bytes, version), version);

  let best: Cell[][] | null = null;
  let bestScore = Number.POSITIVE_INFINITY;
  for (let mask = 0; mask < 8; mask++) {
    const grid = draw(codewords, version, mask);
    const score = penalty(grid);
    if (score < bestScore) {
      bestScore = score;
      best = grid;
    }
  }

  return (best as Cell[][]).map((row) => row.map((cell) => cell.dark));
}

/**
 * The code as one SVG path.
 *
 * One path rather than a rectangle per module: a version 9 code has 2809 of
 * them, and 2809 elements is a page that scrolls badly on a phone for no
 * benefit. The quiet zone is included, because a code without one does not
 * scan.
 */
export function toPath(matrix: Matrix): { path: string; size: number } {
  const quiet = 4;
  const size = matrix.length + quiet * 2;

  const parts: string[] = [];
  for (let r = 0; r < matrix.length; r++) {
    for (let c = 0; c < matrix.length; c++) {
      if ((matrix[r] as boolean[])[c]) parts.push(`M${c + quiet} ${r + quiet}h1v1h-1z`);
    }
  }
  return { path: parts.join(""), size };
}
