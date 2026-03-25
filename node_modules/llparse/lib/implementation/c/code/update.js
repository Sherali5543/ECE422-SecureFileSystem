"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Update = void 0;
const field_1 = require("./field");
class Update extends field_1.Field {
    doBuild(ctx, out) {
        out.push(`${this.field(ctx)} = ${this.ref.value};`);
        out.push('return 0;');
    }
}
exports.Update = Update;
//# sourceMappingURL=update.js.map