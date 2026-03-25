import { Node } from './node';
/**
 * This class finds all reachable nodes
 */
export declare class Reachability {
    /**
     * Build and return list of reachable nodes.
     */
    build(root: Node): ReadonlyArray<Node>;
}
