"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SpanEnd = void 0;
const base_1 = require("./base");
class SpanEnd extends base_1.Node {
    constructor(id, field, callback) {
        super(id);
        this.field = field;
        this.callback = callback;
    }
}
exports.SpanEnd = SpanEnd;
//# sourceMappingURL=span-end.js.map