"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TrieSingle = void 0;
const node_1 = require("./node");
class TrieSingle extends node_1.TrieNode {
    constructor(children, otherwise) {
        super();
        this.children = children;
        this.otherwise = otherwise;
    }
}
exports.TrieSingle = TrieSingle;
//# sourceMappingURL=single.js.map