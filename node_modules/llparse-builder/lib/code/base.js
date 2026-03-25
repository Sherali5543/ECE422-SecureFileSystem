"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Code = void 0;
/**
 * Base code class.
 */
class Code {
    /**
     * @param signature  Code signature to be used. `match` means that code takes
     *                   no input value (from `.select()`), otherwise it must be
     *                   `value`
     * @param name       External function or intrinsic name.
     */
    constructor(signature, name) {
        this.signature = signature;
        this.name = name;
    }
}
exports.Code = Code;
//# sourceMappingURL=base.js.map