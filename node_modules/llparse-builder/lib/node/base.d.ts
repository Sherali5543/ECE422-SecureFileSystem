import { Edge } from '../edge';
/**
 * Base class for all graph nodes.
 */
export declare abstract class Node {
    readonly name: string;
    private otherwiseEdge;
    private privEdges;
    /**
     * @param name  Node name
     */
    constructor(name: string);
    /**
     * Create an otherwise edge to node `node`.
     *
     * This edge is executed when no other edges match current input. No
     * characters are consumed upon transition.
     *
     * NOTE: At most one otherwise (skipping or not) edge can be set, most nodes
     * except `Error` require it.
     *
     * @param node  Target node
     */
    otherwise(node: Node): this;
    /**
     * Create a skipping otherwise edge to node `node`.
     *
     * This edge is executed when no other edges match current input. Single
     * character is consumed upon transition.
     *
     * NOTE: At most one otherwise (skipping or not) edge can be set, most nodes
     * except `Error` require it.
     *
     * @param node  Target node
     */
    skipTo(node: Node): this;
    /** Get otherwise edge. */
    getOtherwiseEdge(): Edge | undefined;
    /** Get list of all non-otherwise edges. */
    getEdges(): ReadonlyArray<Edge>;
    /** Get list of all edges (including otherwise, if present). */
    getAllEdges(): ReadonlyArray<Edge>;
    /** Get iterator through all non-otherwise edges. */
    [Symbol.iterator](): Iterator<Edge>;
    protected addEdge(edge: Edge): void;
}
