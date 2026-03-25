import { Field } from './field';
export interface IMulAddOptions {
    readonly base: number;
    readonly max?: number;
    readonly signed: boolean;
}
export declare class MulAdd extends Field {
    readonly options: IMulAddOptions;
    constructor(name: string, field: string, options: IMulAddOptions);
}
