"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Field = void 0;
const base_1 = require("./base");
class Field extends base_1.Code {
    build(ctx, out) {
        out.push(`int ${this.ref.name}(`);
        out.push(`    ${ctx.prefix}_t* ${ctx.stateArg()},`);
        out.push(`    const unsigned char* ${ctx.posArg()},`);
        if (this.ref.signature === 'value') {
            out.push(`    const unsigned char* ${ctx.endPosArg()},`);
            out.push(`    int ${ctx.matchVar()}) {`);
        }
        else {
            out.push(`    const unsigned char* ${ctx.endPosArg()}) {`);
        }
        const tmp = [];
        this.doBuild(ctx, tmp);
        ctx.indent(out, tmp, '  ');
        out.push('}');
    }
    field(ctx) {
        return `${ctx.stateArg()}->${this.ref.field}`;
    }
}
exports.Field = Field;
//# sourceMappingURL=field.js.map