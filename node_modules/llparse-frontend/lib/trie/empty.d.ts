import { node as api } from 'llparse-builder';
import { TrieNode } from './node';
export declare class TrieEmpty extends TrieNode {
    readonly node: api.Node;
    readonly value: number | undefined;
    constructor(node: api.Node, value: number | undefined);
}
