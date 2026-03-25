import { IWrap } from '../wrap';
import { Node } from './base';
import { Match } from './match';
import { Slot } from './slot';
export interface IReadonlyTableEdge {
    readonly keys: ReadonlyArray<number>;
    readonly node: IWrap<Node>;
    readonly noAdvance: boolean;
}
export declare class TableLookup extends Match {
    private readonly privEdges;
    addEdge(edge: IReadonlyTableEdge): void;
    get edges(): ReadonlyArray<IReadonlyTableEdge>;
    protected buildSlots(): Generator<Slot, void, unknown>;
}
