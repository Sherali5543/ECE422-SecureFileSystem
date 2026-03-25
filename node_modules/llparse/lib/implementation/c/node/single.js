"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Single = void 0;
const base_1 = require("./base");
class Single extends base_1.Node {
    doBuild(out) {
        const ctx = this.compilation;
        const otherwise = this.ref.otherwise;
        this.prologue(out);
        const transform = ctx.unwrapTransform(this.ref.transform);
        const current = transform.build(ctx, `*${ctx.posArg()}`);
        out.push(`switch (${current}) {`);
        this.ref.edges.forEach((edge) => {
            let ch;
            // Non-printable ASCII, or single-quote, or forward slash
            if (edge.key < 0x20 || edge.key > 0x7e || edge.key === 0x27 ||
                edge.key === 0x5c) {
                ch = edge.key.toString();
            }
            else {
                ch = `'${String.fromCharCode(edge.key)}'`;
            }
            out.push(`  case ${ch}: {`);
            const tmp = [];
            this.tailTo(tmp, edge);
            ctx.indent(out, tmp, '    ');
            out.push('  }');
        });
        out.push(`  default: {`);
        const tmp = [];
        this.tailTo(tmp, otherwise);
        ctx.indent(out, tmp, '    ');
        out.push('  }');
        out.push(`}`);
    }
}
exports.Single = Single;
//# sourceMappingURL=single.js.map