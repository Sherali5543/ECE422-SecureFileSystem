import { Edge } from 'llparse-builder';
import { TrieEmpty } from './empty';
import { TrieNode } from './node';
import { TrieSequence } from './sequence';
import { TrieSingle } from './single';
export { TrieEmpty, TrieNode, TrieSequence, TrieSingle };
export declare class Trie {
    private readonly name;
    constructor(name: string);
    build(edges: ReadonlyArray<Edge>): undefined | TrieNode;
    private level;
    private slice;
    private sequence;
    private single;
}
