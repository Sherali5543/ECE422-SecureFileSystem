import { Span } from '../span';
import { Node } from './base';
/**
 * Indicates span end.
 *
 * A callback will be invoked with all input data since the most recent of:
 *
 * * Span start invocation
 * * Parser execution
 */
export declare class SpanEnd extends Node {
    readonly span: Span;
    /**
     * @param span  Span instance
     */
    constructor(span: Span);
}
