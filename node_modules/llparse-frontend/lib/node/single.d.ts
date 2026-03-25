import { IWrap } from '../wrap';
import { Node } from './base';
import { Match } from './match';
import { Slot } from './slot';
export interface IReadonlySingleEdge {
    readonly key: number;
    node: IWrap<Node>;
    readonly noAdvance: boolean;
    readonly value: number | undefined;
}
export declare class Single extends Match {
    private readonly privEdges;
    addEdge(edge: IReadonlySingleEdge): void;
    get edges(): ReadonlyArray<IReadonlySingleEdge>;
    protected buildSlots(): Generator<Slot, void, unknown>;
}
