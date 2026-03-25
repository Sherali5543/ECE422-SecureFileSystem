"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SpanEnd = void 0;
const constants_1 = require("../constants");
const base_1 = require("./base");
class SpanEnd extends base_1.Node {
    doBuild(out) {
        out.push('const unsigned char* start;');
        out.push('int err;');
        out.push('');
        const ctx = this.compilation;
        const field = this.ref.field;
        const posField = ctx.spanPosField(field.index);
        // Load start position
        out.push(`start = ${posField};`);
        // ...and reset
        out.push(`${posField} = NULL;`);
        // Invoke callback
        const callback = ctx.buildCode(ctx.unwrapCode(this.ref.callback));
        out.push(`err = ${callback}(${ctx.stateArg()}, start, ${ctx.posArg()});`);
        out.push('if (err != 0) {');
        const tmp = [];
        this.buildError(tmp, 'err');
        ctx.indent(out, tmp, '  ');
        out.push('}');
        const otherwise = this.ref.otherwise;
        this.tailTo(out, otherwise);
    }
    buildError(out, code) {
        const ctx = this.compilation;
        out.push(`${ctx.errorField()} = ${code};`);
        const otherwise = this.ref.otherwise;
        let resumePos = ctx.posArg();
        if (!otherwise.noAdvance) {
            resumePos = `(${resumePos} + 1)`;
        }
        out.push(`${ctx.errorPosField()} = (const char*) ${resumePos};`);
        const resumptionTarget = ctx.unwrapNode(otherwise.node).build(ctx);
        out.push(`${ctx.currentField()} = ` +
            `(void*) (intptr_t) ${resumptionTarget};`);
        out.push(`return ${constants_1.STATE_ERROR};`);
    }
}
exports.SpanEnd = SpanEnd;
//# sourceMappingURL=span-end.js.map