import { Span } from '../code';
import { SpanField } from '../span-field';
import { IUniqueName } from '../utils';
import { IWrap } from '../wrap';
import { Node } from './base';
export declare class SpanStart extends Node {
    readonly field: SpanField;
    readonly callback: IWrap<Span>;
    constructor(id: IUniqueName, field: SpanField, callback: IWrap<Span>);
}
