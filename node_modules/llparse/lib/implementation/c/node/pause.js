"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Pause = void 0;
const constants_1 = require("../constants");
const error_1 = require("./error");
class Pause extends error_1.Error {
    doBuild(out) {
        const ctx = this.compilation;
        this.storeError(out);
        // Recoverable state
        const otherwise = ctx.unwrapNode(this.ref.otherwise.node).build(ctx);
        out.push(`${ctx.currentField()} = ` +
            `(void*) (intptr_t) ${otherwise};`);
        out.push(`return ${constants_1.STATE_ERROR};`);
    }
}
exports.Pause = Pause;
//# sourceMappingURL=pause.js.map