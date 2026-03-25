import * as frontend from 'llparse-frontend';
import source = frontend.source;
export interface IHeaderBuilderOptions {
    readonly prefix: string;
    readonly headerGuard?: string;
    readonly properties: ReadonlyArray<source.Property>;
    readonly spans: ReadonlyArray<frontend.SpanField>;
}
export declare class HeaderBuilder {
    build(options: IHeaderBuilderOptions): string;
}
