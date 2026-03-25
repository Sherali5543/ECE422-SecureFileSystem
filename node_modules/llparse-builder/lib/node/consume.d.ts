import { Node } from './base';
/**
 * This node consumes number of characters specified by state's property with
 * name `field` from the input, and forwards execution to `otherwise` node.
 */
export declare class Consume extends Node {
    readonly field: string;
    /**
     * @param field  State's property name
     */
    constructor(field: string);
}
