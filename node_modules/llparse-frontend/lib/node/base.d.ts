import { IUniqueName } from '../utils';
import { IWrap } from '../wrap';
import { Slot } from './slot';
export interface IReadonlyOtherwiseEdge {
    readonly node: IWrap<Node>;
    readonly noAdvance: boolean;
    readonly value: number | undefined;
}
export declare abstract class Node {
    readonly id: IUniqueName;
    private privOtherwise;
    private privSlots;
    constructor(id: IUniqueName);
    setOtherwise(node: IWrap<Node>, noAdvance: boolean, value?: number): void;
    get otherwise(): IReadonlyOtherwiseEdge | undefined;
    getSlots(): Generator<Slot, void, undefined>;
    protected buildSlots(): Generator<Slot, void, unknown>;
}
