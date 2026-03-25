"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Invoke = void 0;
const base_1 = require("./base");
class Invoke extends base_1.Node {
    doBuild(out) {
        const ctx = this.compilation;
        const code = ctx.unwrapCode(this.ref.code);
        const codeDecl = ctx.buildCode(code);
        const args = [
            ctx.stateArg(),
            ctx.posArg(),
            ctx.endPosArg(),
        ];
        const signature = code.ref.signature;
        if (signature === 'value') {
            args.push(ctx.matchVar());
        }
        out.push(`switch (${codeDecl}(${args.join(', ')})) {`);
        let tmp;
        for (const edge of this.ref.edges) {
            out.push(`  case ${edge.code}:`);
            tmp = [];
            this.tailTo(tmp, {
                noAdvance: true,
                node: edge.node,
                value: undefined,
            });
            ctx.indent(out, tmp, '    ');
        }
        out.push('  default:');
        tmp = [];
        this.tailTo(tmp, this.ref.otherwise);
        ctx.indent(out, tmp, '    ');
        out.push('}');
    }
}
exports.Invoke = Invoke;
//# sourceMappingURL=invoke.js.map