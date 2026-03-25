import * as code from './code';
import * as node from './node';
import { Property, PropertyType } from './property';
import { Span } from './span';
import * as transform from './transform';
export { code, node, transform, Property, PropertyType, Span };
export { Edge } from './edge';
export { LoopChecker } from './loop-checker';
export { ISpanAllocatorResult, SpanAllocator } from './span-allocator';
export { Reachability } from './reachability';
/**
 * Construct parsing graph for later use in `llparse`.
 */
export declare class Builder {
    /**
     * API for creating external callbacks and intrinsic operations.
     */
    readonly code: code.Creator;
    /**
     * API for creating character transforms for use in nodes created with
     * `builder.node()`
     */
    readonly transform: transform.Creator;
    private readonly privProperties;
    /**
     * Create regular node for matching characters and sequences.
     *
     * @param name Node name
     */
    node(name: string): node.Match;
    /**
     * Create terminal error node. Returns error code to user, and sets reason
     * in the parser's state object.
     *
     * This node does not consume any bytes upon execution.
     *
     * @param errorCode Integer error code
     * @param reason    Error description
     */
    error(errorCode: number, reason: string): node.Error;
    /**
     * Create invoke node that calls either external user callback or an
     * intrinsic operation.
     *
     * This node does not consume any bytes upon execution.
     *
     * NOTE: When `.invoke()` is a target of `node().select()` - callback must
     * have signature that accepts `.select()`'s value, otherwise it must be of
     * the signature that takes no such value.
     *
     * @param fn        Code instance to invoke
     * @param map       Object with integer keys and `Node` values. Describes
     *                  nodes that are visited upon receiving particular
     *                  return integer value
     * @param otherwise Convenience `Node` argument. Effect is the same as calling
     *                  `p.invoke(...).otherwise(node)`
     */
    invoke(fn: code.Code, map?: node.IInvokeMap | node.Node, otherwise?: node.Node): node.Invoke;
    /**
     * Create node that consumes number of bytes specified by value of the
     * state's property with name in `field` argument.
     *
     * @param field Property name to use
     */
    consume(field: string): node.Consume;
    /**
     * Create non-terminal node that returns `errorCode` as error number to
     * user, but still allows feeding more data to the parser.
     *
     * This node does not consume any bytes upon execution.
     *
     * @param errorCode Integer error code
     * @param reason    Error description
     */
    pause(errorCode: number, reason: string): node.Pause;
    /**
     * Create Span with given `callback`.
     *
     * @param callback  External span callback, must be result of
     *                  `.code.span(...)`
     */
    span(callback: code.Span): Span;
    /**
     * Allocate space for property in parser's state.
     */
    property(ty: PropertyType, name: string): void;
    /**
     * Return list of all allocated properties in parser's state.
     */
    get properties(): ReadonlyArray<Property>;
}
