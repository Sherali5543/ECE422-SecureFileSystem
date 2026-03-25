"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ID = void 0;
const base_1 = require("./base");
class ID extends base_1.Transform {
    build(ctx, value) {
        // Identity transformation
        return value;
    }
}
exports.ID = ID;
//# sourceMappingURL=id.js.map