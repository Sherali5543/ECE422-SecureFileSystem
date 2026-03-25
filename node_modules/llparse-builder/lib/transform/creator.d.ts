import { Transform } from './base';
/**
 * API for creating character transformations.
 *
 * The results of methods of this class can be used as an argument to:
 * `p.node().transform(...)`.
 */
export declare class Creator {
    /**
     * Unsafe transform to lowercase.
     *
     * The operation of this transformation is equivalent to:
     * `String.fromCharCode(input.charCodeAt(0) | 0x20)`.
     */
    toLowerUnsafe(): Transform;
    /**
     * Safe transform to lowercase.
     */
    toLower(): Transform;
}
