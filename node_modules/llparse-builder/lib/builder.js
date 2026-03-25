"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Builder = exports.Reachability = exports.SpanAllocator = exports.LoopChecker = exports.Edge = exports.Span = exports.Property = exports.transform = exports.node = exports.code = void 0;
const code = require("./code");
exports.code = code;
const node = require("./node");
exports.node = node;
const property_1 = require("./property");
Object.defineProperty(exports, "Property", { enumerable: true, get: function () { return property_1.Property; } });
const span_1 = require("./span");
Object.defineProperty(exports, "Span", { enumerable: true, get: function () { return span_1.Span; } });
const transform = require("./transform");
exports.transform = transform;
var edge_1 = require("./edge");
Object.defineProperty(exports, "Edge", { enumerable: true, get: function () { return edge_1.Edge; } });
var loop_checker_1 = require("./loop-checker");
Object.defineProperty(exports, "LoopChecker", { enumerable: true, get: function () { return loop_checker_1.LoopChecker; } });
var span_allocator_1 = require("./span-allocator");
Object.defineProperty(exports, "SpanAllocator", { enumerable: true, get: function () { return span_allocator_1.SpanAllocator; } });
var reachability_1 = require("./reachability");
Object.defineProperty(exports, "Reachability", { enumerable: true, get: function () { return reachability_1.Reachability; } });
/**
 * Construct parsing graph for later use in `llparse`.
 */
class Builder {
    constructor() {
        /**
         * API for creating external callbacks and intrinsic operations.
         */
        this.code = new code.Creator();
        /**
         * API for creating character transforms for use in nodes created with
         * `builder.node()`
         */
        this.transform = new transform.Creator();
        this.privProperties = new Map();
    }
    // Various nodes
    /**
     * Create regular node for matching characters and sequences.
     *
     * @param name Node name
     */
    node(name) {
        return new node.Match(name);
    }
    /**
     * Create terminal error node. Returns error code to user, and sets reason
     * in the parser's state object.
     *
     * This node does not consume any bytes upon execution.
     *
     * @param errorCode Integer error code
     * @param reason    Error description
     */
    error(errorCode, reason) {
        return new node.Error(errorCode, reason);
    }
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
    invoke(fn, map, otherwise) {
        let res;
        // `.invoke(name)`
        if (map === undefined) {
            res = new node.Invoke(fn, {});
            // `.invoke(name, otherwise)`
        }
        else if (map instanceof node.Node) {
            res = new node.Invoke(fn, {});
            otherwise = map;
        }
        else {
            res = new node.Invoke(fn, map);
        }
        if (otherwise !== undefined) {
            res.otherwise(otherwise);
        }
        return res;
    }
    /**
     * Create node that consumes number of bytes specified by value of the
     * state's property with name in `field` argument.
     *
     * @param field Property name to use
     */
    consume(field) {
        return new node.Consume(field);
    }
    /**
     * Create non-terminal node that returns `errorCode` as error number to
     * user, but still allows feeding more data to the parser.
     *
     * This node does not consume any bytes upon execution.
     *
     * @param errorCode Integer error code
     * @param reason    Error description
     */
    pause(errorCode, reason) {
        return new node.Pause(errorCode, reason);
    }
    // Span
    /**
     * Create Span with given `callback`.
     *
     * @param callback  External span callback, must be result of
     *                  `.code.span(...)`
     */
    span(callback) {
        return new span_1.Span(callback);
    }
    // Custom property API
    /**
     * Allocate space for property in parser's state.
     */
    property(ty, name) {
        if (this.privProperties.has(name)) {
            throw new Error(`Duplicate property with a name: "${name}"`);
        }
        const prop = new property_1.Property(ty, name);
        this.privProperties.set(name, prop);
    }
    /**
     * Return list of all allocated properties in parser's state.
     */
    get properties() {
        return Array.from(this.privProperties.values());
    }
}
exports.Builder = Builder;
//# sourceMappingURL=builder.js.map