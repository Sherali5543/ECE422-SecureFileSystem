"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Error = void 0;
const constants_1 = require("../constants");
const base_1 = require("./base");
class ErrorNode extends base_1.Node {
    storeError(out) {
        const ctx = this.compilation;
        let hexCode;
        if (this.ref.code < 0) {
            hexCode = `-0x` + this.ref.code.toString(16);
        }
        else {
            hexCode = '0x' + this.ref.code.toString(16);
        }
        out.push(`${ctx.errorField()} = ${hexCode};`);
        out.push(`${ctx.reasonField()} = ${ctx.cstring(this.ref.reason)};`);
        out.push(`${ctx.errorPosField()} = (const char*) ${ctx.posArg()};`);
    }
    doBuild(out) {
        this.storeError(out);
        // Non-recoverable state
        out.push(`${this.compilation.currentField()} = ` +
            `(void*) (intptr_t) ${constants_1.STATE_ERROR};`);
        out.push(`return ${constants_1.STATE_ERROR};`);
    }
}
exports.Error = ErrorNode;
//# sourceMappingURL=error.js.map