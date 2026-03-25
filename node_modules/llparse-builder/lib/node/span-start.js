"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SpanStart = void 0;
const base_1 = require("./base");
/**
 * Indicates span start.
 *
 * See `SpanEnd` for details on callback invocation.
 */
class SpanStart extends base_1.Node {
    /**
     * @param span  Span instance
     */
    constructor(span) {
        super(`span_start_${span.callback.name}`);
        this.span = span;
    }
}
exports.SpanStart = SpanStart;
//# sourceMappingURL=span-start.js.map