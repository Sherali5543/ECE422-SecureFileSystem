import { Code, Signature } from './base';
export declare abstract class Field extends Code {
    readonly field: string;
    constructor(signature: Signature, cacheKey: string, name: string, field: string);
}
