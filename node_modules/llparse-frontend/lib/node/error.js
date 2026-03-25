"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Error = void 0;
const base_1 = require("./base");
class Error extends base_1.Node {
    constructor(id, code, reason) {
        super(id);
        this.code = code;
        this.reason = reason;
    }
}
exports.Error = Error;
//# sourceMappingURL=error.js.map