import * as frontend from 'llparse-frontend';
import { Node } from './base';
export declare class SpanEnd extends Node<frontend.node.SpanEnd> {
    doBuild(out: string[]): void;
    private buildError;
}
