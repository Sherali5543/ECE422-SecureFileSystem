"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IsEqual = void 0;
const field_1 = require("./field");
class IsEqual extends field_1.Field {
    doBuild(ctx, out) {
        out.push(`return ${this.field(ctx)} == ${this.ref.value};`);
    }
}
exports.IsEqual = IsEqual;
//# sourceMappingURL=is-equal.js.map