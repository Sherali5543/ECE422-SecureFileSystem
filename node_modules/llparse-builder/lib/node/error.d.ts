import { Node } from './base';
/**
 * This node terminates the execution with an error
 */
declare class NodeError extends Node {
    readonly code: number;
    readonly reason: string;
    /**
     * @param code    Error code to return to user
     * @param reason  Error description to store in parser's state
     */
    constructor(code: number, reason: string);
    /** `.otherwise()` is not supported on this type of node */
    otherwise(node: Node): this;
    /** `.skipTo()` is not supported on this type of node */
    skipTo(node: Node): this;
}
export { NodeError as Error };
