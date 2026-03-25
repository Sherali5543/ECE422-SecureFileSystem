"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Error = void 0;
const assert = require("assert");
const base_1 = require("./base");
/**
 * This node terminates the execution with an error
 */
class NodeError extends base_1.Node {
    /**
     * @param code    Error code to return to user
     * @param reason  Error description to store in parser's state
     */
    constructor(code, reason) {
        super('error');
        this.code = code;
        this.reason = reason;
        assert.strictEqual(code, code | 0, 'code must be integer');
    }
    /** `.otherwise()` is not supported on this type of node */
    otherwise(node) { throw new Error('Not supported'); }
    /** `.skipTo()` is not supported on this type of node */
    skipTo(node) { throw new Error('Not supported'); }
}
exports.Error = NodeError;
//# sourceMappingURL=error.js.map