import { Node } from '../node';
/**
 * This class implements a loop checker pass. The goal of this pass is to verify
 * that the graph doesn't contain infinite loops.
 */
export declare class LoopChecker {
    private readonly lattice;
    private readonly terminatedCache;
    /**
     * Run loop checker pass on a graph starting from `root`.
     *
     * Throws on failure.
     *
     * @param root  Graph root node
     */
    check(root: Node): void;
    private clear;
    private propagate;
    private update;
    private terminate;
    private visit;
}
