"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Creator = void 0;
const code = require("./");
/**
 * API for creating external callbacks and intrinsic operations.
 */
class Creator {
    // Callbacks to external C functions
    /**
     * Create an external callback that **has no** `value` argument.
     *
     * This callback can be used in all `Invoke` nodes except those that are
     * targets of `.select()` method.
     *
     * C signature of callback must be:
     *
     * ```c
     * int name(llparse_t* state, const char* p, const char* endp)
     * ```
     *
     * Where `llparse_t` is parser state's type name.
     *
     * @param name External function name.
     */
    match(name) {
        return new code.Match(name);
    }
    /**
     * Create an external callback that **has** `value` argument.
     *
     * This callback can be used only in `Invoke` nodes that are targets of
     * `.select()` method.
     *
     * C signature of callback must be:
     *
     * ```c
     * int name(llparse_t* state, const char* p, const char* endp, int value)
     * ```
     *
     * Where `llparse_t` is parser state's type name.
     *
     * @param name External function name.
     */
    value(name) {
        return new code.Value(name);
    }
    /**
     * Create an external span callback.
     *
     * This callback can be used only in `Span` constructor.
     *
     * C signature of callback must be:
     *
     * ```c
     * int name(llparse_t* state, const char* p, const char* endp)
     * ```
     *
     * NOTE: non-zero return value is treated as resumable error.
     *
     * @param name External function name.
     */
    span(name) {
        return new code.Span(name);
    }
    // Helpers
    /**
     * Intrinsic operation. Stores `value` from `.select()` node into the state's
     * property with the name specified by `field`, returns zero.
     *
     *   state[field] = value;
     *   return 0;
     *
     * @param field  Property name
     */
    store(field) {
        return new code.Store(field);
    }
    /**
     * Intrinsic operation. Loads and returns state's property with the name
     * specified by `field`.
     *
     * The value of the property is either truncated or zero-extended to fit into
     * 32-bit unsigned integer.
     *
     *   return state[field];
     *
     * @param field  Property name.
     */
    load(field) {
        return new code.Load(field);
    }
    /**
     * Intrinsic operation. Takes `value` from `.select()`, state's property
     * with the name `field` and does:
     *
     *   field = state[field];
     *   field *= options.base;
     *   field += value;
     *   state[field] = field;
     *   return 0;  // or 1 on overflow
     *
     * Return values are:
     *
     * - 0 - success
     * - 1 - overflow
     *
     * @param field    Property name
     * @param options  See `code.MulAdd` documentation.
     */
    mulAdd(field, options) {
        return new code.MulAdd(field, options);
    }
    /**
     * Intrinsic operation. Puts `value` integer into the state's property with
     * the name specified by `field`.
     *
     *   state[field] = value;
     *   return 0;
     *
     * @param field Property name
     * @param value Integer value to be stored into the property.
     */
    update(field, value) {
        return new code.Update(field, value);
    }
    /**
     * Intrinsic operation. Returns 1 if the integer `value` is equal to the
     * state's property with the name specified by `field`.
     *
     *   return state[field] === value ? 1 : 0;
     *
     * @param field Property name
     * @param value Integer value to be checked against.
     */
    isEqual(field, value) {
        return new code.IsEqual(field, value);
    }
    /**
     * Intrinsic operation.
     *
     *   state[field] &= value
     *   return 0;
     *
     * @param field Property name
     * @param value Integer value
     */
    and(field, value) {
        return new code.And(field, value);
    }
    /**
     * Intrinsic operation.
     *
     *   state[field] |= value
     *   return 0;
     *
     * @param field Property name
     * @param value Integer value
     */
    or(field, value) {
        return new code.Or(field, value);
    }
    /**
     * Intrinsic operation.
     *
     *   return (state[field] & value) == value ? 1 : 0;
     *
     * @param field Property name
     * @param value Integer value
     */
    test(field, value) {
        return new code.Test(field, value);
    }
}
exports.Creator = Creator;
//# sourceMappingURL=creator.js.map