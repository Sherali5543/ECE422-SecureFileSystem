"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Field = void 0;
const base_1 = require("./base");
class Field extends base_1.Code {
    constructor(signature, cacheKey, name, field) {
        super(signature, cacheKey, name);
        this.field = field;
    }
}
exports.Field = Field;
//# sourceMappingURL=field.js.map