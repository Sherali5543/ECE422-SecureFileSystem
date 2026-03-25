"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.External = void 0;
const base_1 = require("./base");
class External extends base_1.Code {
    constructor(signature, name) {
        super(signature, 'external_' + name, name);
    }
}
exports.External = External;
//# sourceMappingURL=external.js.map