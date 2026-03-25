"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Load = void 0;
const field_1 = require("./field");
class Load extends field_1.Field {
    doBuild(ctx, out) {
        out.push(`return ${this.field(ctx)};`);
    }
}
exports.Load = Load;
//# sourceMappingURL=load.js.map