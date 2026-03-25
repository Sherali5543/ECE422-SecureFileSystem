"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Reachability = void 0;
/**
 * This class finds all reachable nodes
 */
class Reachability {
    /**
     * Build and return list of reachable nodes.
     */
    build(root) {
        const res = new Set();
        const queue = [root];
        while (queue.length !== 0) {
            const node = queue.pop();
            if (res.has(node)) {
                continue;
            }
            res.add(node);
            for (const edge of node) {
                queue.push(edge.node);
            }
            const otherwise = node.getOtherwiseEdge();
            if (otherwise !== undefined) {
                queue.push(otherwise.node);
            }
        }
        return Array.from(res);
    }
}
exports.Reachability = Reachability;
//# sourceMappingURL=reachability.js.map