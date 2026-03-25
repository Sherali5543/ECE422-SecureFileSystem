"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Span = void 0;
const node_1 = require("./node");
/**
 * Spans are used for notifying parser user about matched data. Each byte after
 * span start will be sent to the span callback until span end is called.
 */
class Span {
    /**
     * @param callback  External callback, must be `code.span(...)` result.
     */
    constructor(callback) {
        this.callback = callback;
        this.startCache = new Map();
        this.endCache = new Map();
    }
    /**
     * Create `SpanStart` that indicates the start of the span.
     *
     * @param otherwise Optional convenience value. Same as calling
     *                  `span.start().otherwise(...)`
     */
    start(otherwise) {
        if (otherwise !== undefined && this.startCache.has(otherwise)) {
            return this.startCache.get(otherwise);
        }
        const res = new node_1.SpanStart(this);
        if (otherwise !== undefined) {
            res.otherwise(otherwise);
            this.startCache.set(otherwise, res);
        }
        return res;
    }
    /**
     * Create `SpanEnd` that indicates the end of the span.
     *
     * @param otherwise Optional convenience value. Same as calling
     *                  `span.end().otherwise(...)`
     */
    end(otherwise) {
        if (otherwise !== undefined && this.endCache.has(otherwise)) {
            return this.endCache.get(otherwise);
        }
        const res = new node_1.SpanEnd(this);
        if (otherwise !== undefined) {
            res.otherwise(otherwise);
            this.endCache.set(otherwise, res);
        }
        return res;
    }
}
exports.Span = Span;
//# sourceMappingURL=span.js.map