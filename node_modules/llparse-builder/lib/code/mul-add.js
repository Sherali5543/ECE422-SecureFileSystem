"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MulAdd = void 0;
const field_1 = require("./field");
class MulAdd extends field_1.Field {
    constructor(field, options) {
        super('value', 'mul_add', field);
        this.options = options;
    }
}
exports.MulAdd = MulAdd;
//# sourceMappingURL=mul-add.js.map