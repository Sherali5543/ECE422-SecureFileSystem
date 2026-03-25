import { Node } from './base';
/**
 * This returns the specified error code, but makes the resumption to
 * `otherwise` target possible.
 */
export declare class Pause extends Node {
    readonly code: number;
    readonly reason: string;
    /**
     * @param code    Error code to return
     * @param reason  Error description
     */
    constructor(code: number, reason: string);
    /**
     * `.skipTo()` is not supported on this type of node, please use
     * `.otherwise()`
     */
    skipTo(node: Node): this;
}
