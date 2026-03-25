import { IWrap } from '../wrap';
export declare class ContainerWrap<T> {
    readonly ref: T;
    protected readonly map: Map<string, IWrap<T>>;
    constructor(ref: T);
    get<R extends IWrap<T>>(key: string): R;
}
