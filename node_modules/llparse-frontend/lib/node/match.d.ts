import { Transform } from '../transform';
import { IWrap } from '../wrap';
import { Node } from './base';
export declare class Match extends Node {
    transform?: IWrap<Transform>;
    setTransform(transform: IWrap<Transform>): void;
}
