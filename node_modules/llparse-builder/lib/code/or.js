"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Or = void 0;
const field_value_1 = require("./field-value");
class Or extends field_value_1.FieldValue {
    constructor(field, value) {
        super('match', 'or', field, value);
    }
}
exports.Or = Or;
//# sourceMappingURL=or.js.map