"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Lattice = void 0;
const assert = require("assert");
const MAX_VALUE = 256;
const WORD_SIZE = 32;
const SIZE = (MAX_VALUE / WORD_SIZE) | 0;
const WORD_FILL = -1 | 0;
assert.strictEqual(MAX_VALUE % WORD_SIZE, 0);
/**
 * A fixed-size bitfield, really
 */
class Lattice {
    constructor(value) {
        this.words = new Array(SIZE).fill(value === 'any' ? WORD_FILL : 0);
        if (Array.isArray(value)) {
            for (const single of value) {
                this.add(single);
            }
        }
    }
    check(bit) {
        assert(0 <= bit && bit < MAX_VALUE, 'Invalid bit');
        const index = (bit / WORD_SIZE) | 0;
        const off = bit % WORD_SIZE;
        return (this.words[index] & (1 << off)) !== 0;
    }
    union(other) {
        const result = new Lattice('empty');
        for (let i = 0; i < SIZE; i++) {
            result.words[i] = this.words[i] | other.words[i];
        }
        return result;
    }
    intersect(other) {
        const result = new Lattice('empty');
        for (let i = 0; i < SIZE; i++) {
            result.words[i] = this.words[i] & other.words[i];
        }
        return result;
    }
    subtract(other) {
        const result = new Lattice('empty');
        for (let i = 0; i < SIZE; i++) {
            result.words[i] = this.words[i] & (~other.words[i]);
        }
        return result;
    }
    isEqual(other) {
        if (this === other) {
            return true;
        }
        for (let i = 0; i < SIZE; i++) {
            if (this.words[i] !== other.words[i]) {
                return false;
            }
        }
        return true;
    }
    *[Symbol.iterator]() {
        // TODO(indutny): improve speed if needed
        for (let i = 0; i < MAX_VALUE; i++) {
            if (this.check(i)) {
                yield i;
            }
        }
    }
    toJSON() {
        let isEmpty = true;
        let isFull = true;
        for (let i = 0; i < SIZE; i++) {
            if (this.words[i] !== 0) {
                isEmpty = false;
            }
            if (this.words[i] !== WORD_FILL) {
                isFull = false;
            }
        }
        if (isEmpty) {
            return 'empty';
        }
        if (isFull) {
            return 'any';
        }
        return Array.from(this);
    }
    // Private
    add(bit) {
        assert(0 <= bit && bit < MAX_VALUE, 'Invalid bit');
        const index = (bit / WORD_SIZE) | 0;
        const off = bit % WORD_SIZE;
        this.words[index] |= 1 << off;
    }
}
exports.Lattice = Lattice;
//# sourceMappingURL=lattice.js.map