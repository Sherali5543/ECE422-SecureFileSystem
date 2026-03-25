import * as frontend from 'llparse-frontend';
import { Node } from './base';
export declare class Empty extends Node<frontend.node.Empty> {
    doBuild(out: string[]): void;
}
