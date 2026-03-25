"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Node = void 0;
const assert = require("assert");
const binarySearch = require("binary-search");
const edge_1 = require("../edge");
/**
 * Base class for all graph nodes.
 */
class Node {
    /**
     * @param name  Node name
     */
    constructor(name) {
        this.name = name;
        this.privEdges = [];
        // no-op
    }
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
    otherwise(node) {
        if (this.otherwiseEdge !== undefined) {
            throw new Error('Node already has `otherwise` or `skipTo`');
        }
        this.otherwiseEdge = new edge_1.Edge(node, true, undefined, undefined);
        return this;
    }
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
    skipTo(node) {
        if (this.otherwiseEdge !== undefined) {
            throw new Error('Node already has `otherwise` or `skipTo`');
        }
        this.otherwiseEdge = new edge_1.Edge(node, false, undefined, undefined);
        return this;
    }
    // Limited public use
    /** Get otherwise edge. */
    getOtherwiseEdge() {
        return this.otherwiseEdge;
    }
    /** Get list of all non-otherwise edges. */
    getEdges() {
        return this.privEdges;
    }
    /** Get list of all edges (including otherwise, if present). */
    getAllEdges() {
        const res = this.privEdges;
        if (this.otherwiseEdge === undefined) {
            return res;
        }
        else {
            return res.concat(this.otherwiseEdge);
        }
    }
    /** Get iterator through all non-otherwise edges. */
    *[Symbol.iterator]() {
        yield* this.privEdges;
    }
    // Internal
    addEdge(edge) {
        assert.notStrictEqual(edge.key, undefined);
        const index = binarySearch(this.privEdges, edge, edge_1.Edge.compare);
        assert(index < 0, 'Attempting to create duplicate edge');
        this.privEdges.splice(-1 - index, 0, edge);
    }
}
exports.Node = Node;
//# sourceMappingURL=base.js.map