import { IUniqueName } from '../utils';
import { Node } from './base';
export declare class Consume extends Node {
    readonly field: string;
    constructor(id: IUniqueName, field: string);
}
