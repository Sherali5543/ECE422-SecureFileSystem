import * as frontend from 'llparse-frontend';
import { Compilation } from '../compilation';
import { Code } from './base';
export declare abstract class External<T extends frontend.code.External> extends Code<T> {
    build(ctx: Compilation, out: string[]): void;
}
