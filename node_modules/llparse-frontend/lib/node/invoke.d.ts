import { Code } from '../code';
import { IUniqueName } from '../utils';
import { IWrap } from '../wrap';
import { Node } from './base';
import { Slot } from './slot';
export interface IReadonlyInvokeEdge {
    readonly code: number;
    readonly node: IWrap<Node>;
}
export declare class Invoke extends Node {
    readonly code: IWrap<Code>;
    private readonly privEdges;
    constructor(id: IUniqueName, code: IWrap<Code>);
    addEdge(code: number, node: IWrap<Node>): void;
    get edges(): ReadonlyArray<IReadonlyInvokeEdge>;
    protected buildSlots(): Generator<Slot, void, unknown>;
}
