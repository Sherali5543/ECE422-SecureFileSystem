import * as frontend from 'llparse-frontend';
import { Node } from './base';
export declare class Consume extends Node<frontend.node.Consume> {
    doBuild(out: string[]): void;
}
