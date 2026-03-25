import { Span as SpanCallback } from './code';
import { Node, SpanEnd, SpanStart } from './node';
/**
 * Spans are used for notifying parser user about matched data. Each byte after
 * span start will be sent to the span callback until span end is called.
 */
export declare class Span {
    readonly callback: SpanCallback;
    private readonly startCache;
    private readonly endCache;
    /**
     * @param callback  External callback, must be `code.span(...)` result.
     */
    constructor(callback: SpanCallback);
    /**
     * Create `SpanStart` that indicates the start of the span.
     *
     * @param otherwise Optional convenience value. Same as calling
     *                  `span.start().otherwise(...)`
     */
    start(otherwise?: Node): SpanStart;
    /**
     * Create `SpanEnd` that indicates the end of the span.
     *
     * @param otherwise Optional convenience value. Same as calling
     *                  `span.end().otherwise(...)`
     */
    end(otherwise?: Node): SpanEnd;
}
