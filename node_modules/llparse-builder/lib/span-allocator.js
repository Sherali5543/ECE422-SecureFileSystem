"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SpanAllocator = void 0;
const assert = require("assert");
const debugAPI = require("debug");
const node_1 = require("./node");
const reachability_1 = require("./reachability");
const debug = debugAPI('llparse-builder:span-allocator');
function id(node) {
    return node.span;
}
class SpanAllocator {
    allocate(root) {
        const r = new reachability_1.Reachability();
        const nodes = r.build(root);
        const info = this.computeActive(nodes);
        this.check(info);
        const overlap = this.computeOverlap(info);
        return this.color(info.spans, overlap);
    }
    computeActive(nodes) {
        const activeMap = new Map();
        nodes.forEach((node) => activeMap.set(node, new Set()));
        const queue = new Set(nodes);
        const spans = new Set();
        for (const node of queue) {
            queue.delete(node);
            const active = activeMap.get(node);
            if (node instanceof node_1.SpanStart) {
                const span = id(node);
                spans.add(span);
                active.add(span);
            }
            active.forEach((span) => {
                // Don't propagate span past the spanEnd
                if (node instanceof node_1.SpanEnd && span === id(node)) {
                    return;
                }
                node.getAllEdges().forEach((edge) => {
                    const edgeNode = edge.node;
                    // Disallow loops
                    if (edgeNode instanceof node_1.SpanStart) {
                        assert.notStrictEqual(id(edgeNode), span, `Detected loop in span "${span.callback.name}", started ` +
                            `at "${node.name}"`);
                    }
                    const edgeActive = activeMap.get(edgeNode);
                    if (edgeActive.has(span)) {
                        return;
                    }
                    edgeActive.add(span);
                    queue.add(edgeNode);
                });
            });
        }
        return { active: activeMap, spans: Array.from(spans) };
    }
    check(info) {
        debug('check start');
        for (const [node, spans] of info.active) {
            for (const edge of node.getAllEdges()) {
                if (edge.node instanceof node_1.SpanStart) {
                    continue;
                }
                // Skip terminal nodes
                if (edge.node.getAllEdges().length === 0) {
                    continue;
                }
                debug('checking edge from %j to %j', node.name, edge.node.name);
                const edgeSpans = info.active.get(edge.node);
                for (const subSpan of edgeSpans) {
                    assert(spans.has(subSpan), `Unmatched span end for "${subSpan.callback.name}" ` +
                        `at "${edge.node.name}", coming from "${node.name}"`);
                }
                if (edge.node instanceof node_1.SpanEnd) {
                    const span = id(edge.node);
                    assert(spans.has(span), `Unmatched span end for "${span.callback.name}"`);
                }
            }
        }
    }
    computeOverlap(info) {
        const active = info.active;
        const overlap = new Map();
        info.spans.forEach((span) => overlap.set(span, new Set()));
        active.forEach((spans) => {
            spans.forEach((one) => {
                const set = overlap.get(one);
                spans.forEach((other) => {
                    if (other !== one) {
                        set.add(other);
                    }
                });
            });
        });
        return overlap;
    }
    color(spans, overlapMap) {
        let max = -1;
        const colors = new Map();
        const allocate = (span) => {
            if (colors.has(span)) {
                return colors.get(span);
            }
            const overlap = overlapMap.get(span);
            // See which colors are already used
            const used = new Set();
            for (const subSpan of overlap) {
                if (colors.has(subSpan)) {
                    used.add(colors.get(subSpan));
                }
            }
            // Find minimum available color
            let i;
            for (i = 0; used.has(i); i++) {
                // no-op
            }
            max = Math.max(max, i);
            colors.set(span, i);
            return i;
        };
        const map = new Map();
        spans.forEach((span) => map.set(span, allocate(span)));
        const concurrency = new Array(max + 1);
        for (let i = 0; i < concurrency.length; i++) {
            concurrency[i] = [];
        }
        spans.forEach((span) => concurrency[allocate(span)].push(span));
        return { colors: map, concurrency, max };
    }
}
exports.SpanAllocator = SpanAllocator;
//# sourceMappingURL=span-allocator.js.map