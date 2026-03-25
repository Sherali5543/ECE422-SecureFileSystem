"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SpanEnd = void 0;
const base_1 = require("./base");
/**
 * Indicates span end.
 *
 * A callback will be invoked with all input data since the most recent of:
 *
 * * Span start invocation
 * * Parser execution
 */
class SpanEnd extends base_1.Node {
    /**
     * @param span  Span instance
     */
    constructor(span) {
        super(`span_end_${span.callback.name}`);
        this.span = span;
    }
}
exports.SpanEnd = SpanEnd;
//# sourceMappingURL=span-end.js.map