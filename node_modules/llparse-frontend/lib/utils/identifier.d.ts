export interface IUniqueName {
    readonly name: string;
    readonly originalName: string;
}
export declare class Identifier {
    private readonly prefix;
    private readonly postfix;
    private readonly ns;
    constructor(prefix?: string, postfix?: string);
    id(name: string): IUniqueName;
}
