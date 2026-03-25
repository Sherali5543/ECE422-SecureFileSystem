"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.toBuffer = void 0;
const assert = require("assert");
const buffer_1 = require("buffer");
/**
 * Internal
 */
function toBuffer(value) {
    let res;
    if (buffer_1.Buffer.isBuffer(value)) {
        res = value;
    }
    else if (typeof value === 'string') {
        res = buffer_1.Buffer.from(value);
    }
    else {
        assert(0 <= value && value <= 0xff, 'Invalid byte value');
        res = buffer_1.Buffer.from([value]);
    }
    assert(res.length >= 1, 'Invalid key length');
    return res;
}
exports.toBuffer = toBuffer;
//# sourceMappingURL=utils.js.map