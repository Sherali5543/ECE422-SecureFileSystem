import { Node } from './node';
import { Span } from './span';
export interface ISpanAllocatorResult {
    readonly colors: ReadonlyMap<Span, number>;
    readonly concurrency: ReadonlyArray<ReadonlyArray<Span>>;
    readonly max: number;
}
export declare class SpanAllocator {
    allocate(root: Node): ISpanAllocatorResult;
    private computeActive;
    private check;
    private computeOverlap;
    private color;
}
