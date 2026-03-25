import * as frontend from 'llparse-frontend';
import { Node } from './base';
export declare class Single extends Node<frontend.node.Single> {
    doBuild(out: string[]): void;
}
