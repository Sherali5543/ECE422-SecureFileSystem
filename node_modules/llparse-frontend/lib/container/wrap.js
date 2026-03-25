"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ContainerWrap = void 0;
const assert = require("assert");
class ContainerWrap {
    constructor(ref) {
        this.ref = ref;
        this.map = new Map();
    }
    get(key) {
        assert(this.map.has(key), `Unknown implementation key "${key}"`);
        return this.map.get(key);
    }
}
exports.ContainerWrap = ContainerWrap;
//# sourceMappingURL=wrap.js.map