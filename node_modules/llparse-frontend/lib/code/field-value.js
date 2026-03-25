"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FieldValue = void 0;
const assert = require("assert");
const field_1 = require("./field");
class FieldValue extends field_1.Field {
    constructor(signature, cacheKey, name, field, value) {
        super(signature, cacheKey, name, field);
        this.value = value;
        assert.strictEqual(value, value | 0, 'FieldValue `value` must be integer');
    }
}
exports.FieldValue = FieldValue;
//# sourceMappingURL=field-value.js.map