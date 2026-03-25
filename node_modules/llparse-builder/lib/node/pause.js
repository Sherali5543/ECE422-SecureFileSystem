"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Pause = void 0;
const assert = require("assert");
const base_1 = require("./base");
/**
 * This returns the specified error code, but makes the resumption to
 * `otherwise` target possible.
 */
class Pause extends base_1.Node {
    /**
     * @param code    Error code to return
     * @param reason  Error description
     */
    constructor(code, reason) {
        super('pause');
        this.code = code;
        this.reason = reason;
        assert.strictEqual(code, code | 0, 'code must be integer');
    }
    /**
     * `.skipTo()` is not supported on this type of node, please use
     * `.otherwise()`
     */
    skipTo(node) {
        throw new Error('Not supported, please use `pause.otherwise()`');
    }
}
exports.Pause = Pause;
//# sourceMappingURL=pause.js.map