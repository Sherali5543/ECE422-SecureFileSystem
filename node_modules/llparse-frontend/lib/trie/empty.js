"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TrieEmpty = void 0;
const node_1 = require("./node");
class TrieEmpty extends node_1.TrieNode {
    constructor(node, value) {
        super();
        this.node = node;
        this.value = value;
    }
}
exports.TrieEmpty = TrieEmpty;
//# sourceMappingURL=empty.js.map