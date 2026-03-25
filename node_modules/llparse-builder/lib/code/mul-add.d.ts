import { Field } from './field';
/**
 * Options for `code.mulAdd()`.
 */
export interface IMulAddOptions {
    /** Value to multiply the property with in the first step */
    readonly base: number;
    /**
     * Maximum value of the property. If at any point of computation the
     * intermediate result exceeds it - `mulAdd` returns 1 (overflow).
     */
    readonly max?: number;
    /**
     * If `true` - all arithmetics perfomed by `mulAdd` will be signed.
     *
     * Default value: `false`
     */
    readonly signed?: boolean;
}
export declare class MulAdd extends Field {
    readonly options: IMulAddOptions;
    constructor(field: string, options: IMulAddOptions);
}
