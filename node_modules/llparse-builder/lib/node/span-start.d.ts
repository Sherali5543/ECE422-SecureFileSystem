import { Span } from '../span';
import { Node } from './base';
/**
 * Indicates span start.
 *
 * See `SpanEnd` for details on callback invocation.
 */
export declare class SpanStart extends Node {
    readonly span: Span;
    /**
     * @param span  Span instance
     */
    constructor(span: Span);
}
