"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Store = void 0;
const field_1 = require("./field");
class Store extends field_1.Field {
    doBuild(ctx, out) {
        out.push(`${this.field(ctx)} = ${ctx.matchVar()};`);
        out.push('return 0;');
    }
}
exports.Store = Store;
//# sourceMappingURL=store.js.map