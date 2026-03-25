"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ToLowerUnsafe = void 0;
const base_1 = require("./base");
class ToLowerUnsafe extends base_1.Transform {
    build(ctx, value) {
        return `((${value}) | 0x20)`;
    }
}
exports.ToLowerUnsafe = ToLowerUnsafe;
//# sourceMappingURL=to-lower-unsafe.js.map