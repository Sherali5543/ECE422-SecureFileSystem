"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SpanStart = void 0;
const base_1 = require("./base");
class SpanStart extends base_1.Node {
    constructor(id, field, callback) {
        super(id);
        this.field = field;
        this.callback = callback;
    }
}
exports.SpanStart = SpanStart;
//# sourceMappingURL=span-start.js.map