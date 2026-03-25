"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Sequence = void 0;
const assert = require("assert");
const match_1 = require("./match");
const slot_1 = require("./slot");
class Sequence extends match_1.Match {
    constructor(id, select) {
        super(id);
        this.select = select;
    }
    setEdge(node, value) {
        assert.strictEqual(this.privEdge, undefined);
        this.privEdge = { node, value };
    }
    get edge() {
        return this.privEdge;
    }
    *buildSlots() {
        const edge = this.privEdge;
        if (edge !== undefined) {
            yield new slot_1.Slot(edge.node, (value) => edge.node = value);
        }
        yield* super.buildSlots();
    }
}
exports.Sequence = Sequence;
//# sourceMappingURL=sequence.js.map