import { IUniqueName } from '../utils';
import { Node } from './base';
export declare class Error extends Node {
    readonly code: number;
    readonly reason: string;
    constructor(id: IUniqueName, code: number, reason: string);
}
