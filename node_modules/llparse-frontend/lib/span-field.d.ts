import { Span } from './code';
import { IWrap } from './wrap';
export declare class SpanField {
    readonly index: number;
    readonly callbacks: ReadonlyArray<IWrap<Span>>;
    constructor(index: number, callbacks: ReadonlyArray<IWrap<Span>>);
}
