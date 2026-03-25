"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Node = void 0;
const slot_1 = require("./slot");
class Node {
    constructor(id) {
        this.id = id;
    }
    setOtherwise(node, noAdvance, value) {
        this.privOtherwise = { node, noAdvance, value };
    }
    get otherwise() {
        return this.privOtherwise;
    }
    *getSlots() {
        if (this.privSlots === undefined) {
            this.privSlots = Array.from(this.buildSlots());
        }
        yield* this.privSlots;
    }
    *buildSlots() {
        const otherwise = this.privOtherwise;
        if (otherwise !== undefined) {
            yield new slot_1.Slot(otherwise.node, (value) => otherwise.node = value);
        }
    }
}
exports.Node = Node;
//# sourceMappingURL=base.js.map