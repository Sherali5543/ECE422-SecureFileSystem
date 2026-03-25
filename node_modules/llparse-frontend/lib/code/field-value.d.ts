import { Signature } from './base';
import { Field } from './field';
export declare abstract class FieldValue extends Field {
    readonly value: number;
    constructor(signature: Signature, cacheKey: string, name: string, field: string, value: number);
}
