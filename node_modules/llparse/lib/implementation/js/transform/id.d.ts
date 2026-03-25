import * as frontend from 'llparse-frontend';
import { Compilation } from '../compilation';
import { Transform } from './base';
export declare class ID extends Transform<frontend.transform.ID> {
    build(ctx: Compilation, value: string): string;
}
