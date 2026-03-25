import * as frontend from 'llparse-frontend';
import { Node } from './base';
export declare class SpanStart extends Node<frontend.node.SpanStart> {
    doBuild(out: string[]): void;
}
