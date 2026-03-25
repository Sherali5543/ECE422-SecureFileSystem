import * as frontend from 'llparse-frontend';
import { Compilation } from '../compilation';
export declare abstract class Transform<T extends frontend.transform.Transform> {
    readonly ref: T;
    constructor(ref: T);
    abstract build(ctx: Compilation, value: string): string;
}
