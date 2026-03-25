"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FieldValue = void 0;
const field_1 = require("./field");
class FieldValue extends field_1.Field {
    constructor(signature, name, field, value) {
        super(signature, name, field);
        this.value = value;
    }
}
exports.FieldValue = FieldValue;
//# sourceMappingURL=field-value.js.map