"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Identifier = void 0;
class Identifier {
    constructor(prefix = '', postfix = '') {
        this.prefix = prefix;
        this.postfix = postfix;
        this.ns = new Set();
    }
    id(name) {
        let target = this.prefix + name + this.postfix;
        if (this.ns.has(target)) {
            let i = 1;
            for (; i < this.ns.size; i++) {
                if (!this.ns.has(target + '_' + i)) {
                    break;
                }
            }
            target += '_' + i;
        }
        this.ns.add(target);
        return {
            name: target,
            originalName: name,
        };
    }
}
exports.Identifier = Identifier;
//# sourceMappingURL=identifier.js.map