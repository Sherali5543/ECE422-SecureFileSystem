import { Code } from '../code';
import { Node } from './base';
/**
 * Map of return codes of the callback. Each key is a return code,
 * value is the target node that must be executed upon getting such return code.
 */
export interface IInvokeMap {
    readonly [key: number]: Node;
}
/**
 * This node invokes either external callback or intrinsic code and passes the
 * execution to either a target from a `map` (if the return code matches one of
 * registered in it), or to `otherwise` node.
 */
export declare class Invoke extends Node {
    readonly code: Code;
    /**
     * @param code  External callback or intrinsic code. Can be created with
     *              `builder.code.*()` methods.
     * @param map   Map from callback return codes to target nodes
     */
    constructor(code: Code, map: IInvokeMap);
}
