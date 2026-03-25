import { TrieEmpty } from './empty';
import { TrieNode } from './node';
export interface ITrieSingleChild {
    readonly key: number;
    readonly noAdvance: boolean;
    readonly node: TrieNode;
}
export declare class TrieSingle extends TrieNode {
    readonly children: ReadonlyArray<ITrieSingleChild>;
    readonly otherwise: TrieEmpty | undefined;
    constructor(children: ReadonlyArray<ITrieSingleChild>, otherwise: TrieEmpty | undefined);
}
