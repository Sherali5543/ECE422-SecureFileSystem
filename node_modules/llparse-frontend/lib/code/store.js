"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Store = void 0;
const field_1 = require("./field");
class Store extends field_1.Field {
    constructor(name, field) {
        super('value', `store_${field}`, name, field);
    }
}
exports.Store = Store;
//# sourceMappingURL=store.js.map