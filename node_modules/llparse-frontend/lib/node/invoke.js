"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Invoke = void 0;
const base_1 = require("./base");
const slot_1 = require("./slot");
class Invoke extends base_1.Node {
    constructor(id, code) {
        super(id);
        this.code = code;
        this.privEdges = [];
    }
    addEdge(code, node) {
        this.privEdges.push({ code, node });
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
exports.Invoke = Invoke;
//# sourceMappingURL=invoke.js.map