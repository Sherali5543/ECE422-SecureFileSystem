import { ICodeImplementation } from '../implementation/code';
import { IImplementation } from '../implementation/full';
import { INodeImplementation } from '../implementation/node';
import { ITransformImplementation } from '../implementation/transform';
import { ContainerWrap } from './wrap';
export { ContainerWrap };
export declare class Container {
    private readonly map;
    add(key: string, impl: IImplementation): void;
    build(): IImplementation;
    buildCode(): ICodeImplementation;
    buildNode(): INodeImplementation;
    buildTransform(): ITransformImplementation;
    private combine;
}
