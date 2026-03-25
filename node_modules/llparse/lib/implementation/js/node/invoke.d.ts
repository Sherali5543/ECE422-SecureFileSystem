import * as frontend from 'llparse-frontend';
import { Node } from './base';
export declare class Invoke extends Node<frontend.node.Invoke> {
    doBuild(out: string[]): void;
}
