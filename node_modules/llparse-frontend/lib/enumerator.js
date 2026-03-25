"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Enumerator = void 0;
class Enumerator {
    getAllNodes(root) {
        const nodes = new Set();
        const queue = [root];
        while (queue.length !== 0) {
            const node = queue.pop();
            for (const slot of node.ref.getSlots()) {
                if (nodes.has(slot.node)) {
                    continue;
                }
                nodes.add(slot.node);
                queue.push(slot.node);
            }
        }
        return Array.from(nodes);
    }
}
exports.Enumerator = Enumerator;
//# sourceMappingURL=enumerator.js.map