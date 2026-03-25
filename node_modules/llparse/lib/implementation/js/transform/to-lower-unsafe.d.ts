import * as frontend from 'llparse-frontend';
import { Compilation } from '../compilation';
import { Transform } from './base';
export declare class ToLowerUnsafe extends Transform<frontend.transform.ToLowerUnsafe> {
    build(ctx: Compilation, value: string): string;
}
