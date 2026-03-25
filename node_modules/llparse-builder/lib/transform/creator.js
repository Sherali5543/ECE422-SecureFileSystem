"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Creator = void 0;
const to_lower_1 = require("./to-lower");
const to_lower_unsafe_1 = require("./to-lower-unsafe");
/**
 * API for creating character transformations.
 *
 * The results of methods of this class can be used as an argument to:
 * `p.node().transform(...)`.
 */
class Creator {
    /**
     * Unsafe transform to lowercase.
     *
     * The operation of this transformation is equivalent to:
     * `String.fromCharCode(input.charCodeAt(0) | 0x20)`.
     */
    toLowerUnsafe() {
        return new to_lower_unsafe_1.ToLowerUnsafe();
    }
    /**
     * Safe transform to lowercase.
     */
    toLower() {
        return new to_lower_1.ToLower();
    }
}
exports.Creator = Creator;
//# sourceMappingURL=creator.js.map