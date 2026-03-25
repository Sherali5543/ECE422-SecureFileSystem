"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Test = void 0;
const field_1 = require("./field");
class Test extends field_1.Field {
    doBuild(ctx, out) {
        const value = this.ref.value;
        out.push(`return (${this.field(ctx)} & ${value}) == ${value};`);
    }
}
exports.Test = Test;
//# sourceMappingURL=test.js.map