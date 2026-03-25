"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TableLookup = void 0;
const match_1 = require("./match");
const slot_1 = require("./slot");
class TableLookup extends match_1.Match {
    constructor() {
        super(...arguments);
        this.privEdges = [];
    }
    addEdge(edge) {
        this.privEdges.push({
            keys: edge.keys,
            noAdvance: edge.noAdvance,
            node: edge.node,
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
exports.TableLookup = TableLookup;
//# sourceMappingURL=table-lookup.js.map