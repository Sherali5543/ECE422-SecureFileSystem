"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Field = void 0;
const assert = require("assert");
const base_1 = require("./base");
class Field extends base_1.Code {
    constructor(signature, name, field) {
        super(signature, name + '_' + field);
        this.field = field;
        assert(!/^_/.test(field), 'Can\'t access internal field from user code');
    }
}
exports.Field = Field;
//# sourceMappingURL=field.js.map