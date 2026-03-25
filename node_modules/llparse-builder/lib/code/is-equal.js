"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IsEqual = void 0;
const field_value_1 = require("./field-value");
class IsEqual extends field_value_1.FieldValue {
    constructor(field, value) {
        super('match', 'is_equal', field, value);
    }
}
exports.IsEqual = IsEqual;
//# sourceMappingURL=is-equal.js.map