import { Code, Signature } from './base';
export declare abstract class Field extends Code {
    readonly field: string;
    constructor(signature: Signature, name: string, field: string);
}
