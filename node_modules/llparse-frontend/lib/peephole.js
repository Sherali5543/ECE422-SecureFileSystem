"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Peephole = void 0;
const node_1 = require("./node");
class Peephole {
    optimize(root, nodes) {
        let changed = new Set(nodes);
        while (changed.size !== 0) {
            const previous = changed;
            changed = new Set();
            for (const node of previous) {
                if (this.optimizeNode(node)) {
                    changed.add(node);
                }
            }
        }
        while (root.ref instanceof node_1.Empty) {
            if (!root.ref.otherwise.noAdvance) {
                break;
            }
            root = root.ref.otherwise.node;
        }
        return root;
    }
    optimizeNode(node) {
        let changed = false;
        for (const slot of node.ref.getSlots()) {
            if (!(slot.node.ref instanceof node_1.Empty)) {
                continue;
            }
            const otherwise = slot.node.ref.otherwise;
            // Node actively skips, can't optimize!
            if (!otherwise.noAdvance) {
                continue;
            }
            slot.node = otherwise.node;
            changed = true;
        }
        return changed;
    }
}
exports.Peephole = Peephole;
//# sourceMappingURL=peephole.js.map