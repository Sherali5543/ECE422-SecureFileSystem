"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Single = void 0;
const match_1 = require("./match");
const slot_1 = require("./slot");
class Single extends match_1.Match {
    constructor() {
        super(...arguments);
        this.privEdges = [];
    }
    addEdge(edge) {
        this.privEdges.push({
            key: edge.key,
            noAdvance: edge.noAdvance,
            node: edge.node,
            value: edge.value,
        });
    }
    get edges() {
        return this.privEdges;
    }
    *buildSlots() {
        for (const edge of this.privEdges) {
            yield new slot_1.Slot(edge.node, (value) => edge.node = value);
        }
        yield* super.buildSlots();
    }
}
exports.Single = Single;
//# sourceMappingURL=single.js.map