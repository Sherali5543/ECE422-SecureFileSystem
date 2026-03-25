"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Update = void 0;
const field_value_1 = require("./field-value");
class Update extends field_value_1.FieldValue {
    constructor(field, value) {
        super('match', 'update', field, value);
    }
}
exports.Update = Update;
//# sourceMappingURL=update.js.map