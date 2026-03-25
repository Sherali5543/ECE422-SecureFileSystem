"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Slot = void 0;
class Slot {
    constructor(node, privUpdate) {
        this.privUpdate = privUpdate;
        this.privNode = node;
    }
    get node() {
        return this.privNode;
    }
    set node(value) {
        this.privNode = value;
        this.privUpdate(value);
    }
}
exports.Slot = Slot;
//# sourceMappingURL=slot.js.map