"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TrieSequence = void 0;
const node_1 = require("./node");
class TrieSequence extends node_1.TrieNode {
    constructor(select, child) {
        super();
        this.select = select;
        this.child = child;
    }
}
exports.TrieSequence = TrieSequence;
//# sourceMappingURL=sequence.js.map