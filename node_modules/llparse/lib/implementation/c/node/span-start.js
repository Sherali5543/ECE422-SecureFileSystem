"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SpanStart = void 0;
const base_1 = require("./base");
class SpanStart extends base_1.Node {
    doBuild(out) {
        // Prevent spurious empty spans
        this.prologue(out);
        const ctx = this.compilation;
        const field = this.ref.field;
        const posField = ctx.spanPosField(field.index);
        out.push(`${posField} = (void*) ${ctx.posArg()};`);
        if (field.callbacks.length > 1) {
            const cbField = ctx.spanCbField(field.index);
            const callback = ctx.unwrapCode(this.ref.callback);
            out.push(`${cbField} = ${ctx.buildCode(callback)};`);
        }
        const otherwise = this.ref.otherwise;
        this.tailTo(out, otherwise);
    }
}
exports.SpanStart = SpanStart;
//# sourceMappingURL=span-start.js.map