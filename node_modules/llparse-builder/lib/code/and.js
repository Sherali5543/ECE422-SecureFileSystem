"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.And = void 0;
const field_value_1 = require("./field-value");
class And extends field_value_1.FieldValue {
    constructor(field, value) {
        super('match', 'and', field, value);
    }
}
exports.And = And;
//# sourceMappingURL=and.js.map