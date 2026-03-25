import * as code from './';
/**
 * API for creating external callbacks and intrinsic operations.
 */
export declare class Creator {
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
    match(name: string): code.Match;
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
    value(name: string): code.Value;
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
    span(name: string): code.Span;
    /**
     * Intrinsic operation. Stores `value` from `.select()` node into the state's
     * property with the name specified by `field`, returns zero.
     *
     *   state[field] = value;
     *   return 0;
     *
     * @param field  Property name
     */
    store(field: string): code.Store;
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
    load(field: string): code.Load;
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
    mulAdd(field: string, options: code.IMulAddOptions): code.MulAdd;
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
    update(field: string, value: number): code.Update;
    /**
     * Intrinsic operation. Returns 1 if the integer `value` is equal to the
     * state's property with the name specified by `field`.
     *
     *   return state[field] === value ? 1 : 0;
     *
     * @param field Property name
     * @param value Integer value to be checked against.
     */
    isEqual(field: string, value: number): code.IsEqual;
    /**
     * Intrinsic operation.
     *
     *   state[field] &= value
     *   return 0;
     *
     * @param field Property name
     * @param value Integer value
     */
    and(field: string, value: number): code.And;
    /**
     * Intrinsic operation.
     *
     *   state[field] |= value
     *   return 0;
     *
     * @param field Property name
     * @param value Integer value
     */
    or(field: string, value: number): code.Or;
    /**
     * Intrinsic operation.
     *
     *   return (state[field] & value) == value ? 1 : 0;
     *
     * @param field Property name
     * @param value Integer value
     */
    test(field: string, value: number): code.Test;
}
