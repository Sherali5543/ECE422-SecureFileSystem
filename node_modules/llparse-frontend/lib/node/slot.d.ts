import { IWrap } from '../wrap';
import { Node } from './base';
export declare class Slot {
    private readonly privUpdate;
    private privNode;
    constructor(node: IWrap<Node>, privUpdate: (value: IWrap<Node>) => void);
    get node(): IWrap<Node>;
    set node(value: IWrap<Node>);
}
