import * as frontend from 'llparse-frontend';
import { Node } from './base';
export declare class Sequence extends Node<frontend.node.Sequence> {
    doBuild(out: string[]): void;
}
