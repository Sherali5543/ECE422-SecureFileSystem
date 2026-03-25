import * as frontend from 'llparse-frontend';
export interface ICCompilerOptions {
    readonly debug?: string;
    readonly header?: string;
}
export interface ICPublicOptions {
    readonly header?: string;
}
export declare class CCompiler {
    readonly options: ICCompilerOptions;
    constructor(container: frontend.Container, options: ICCompilerOptions);
    compile(info: frontend.IFrontendResult): string;
    private restartSpans;
    private executeSpans;
}
