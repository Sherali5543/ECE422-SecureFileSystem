import * as frontend from 'llparse-frontend';
import { Compilation } from '../compilation';
import { Code } from './base';
export declare abstract class Field<T extends frontend.code.Field> extends Code<T> {
    build(ctx: Compilation, out: string[]): void;
    protected abstract doBuild(ctx: Compilation, out: string[]): void;
    protected field(ctx: Compilation): string;
}
