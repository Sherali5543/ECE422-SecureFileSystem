import * as frontend from 'llparse-frontend';
import { Error as ErrorNode } from './error';
export declare class Pause extends ErrorNode<frontend.node.Pause> {
    doBuild(out: string[]): void;
}
