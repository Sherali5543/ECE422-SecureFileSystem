"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Property = void 0;
/**
 * Class describing allocated property in parser's state
 */
class Property {
    constructor(ty, name) {
        this.ty = ty;
        this.name = name;
        if (/^_/.test(name)) {
            throw new Error(`Can't use internal property name: "${name}"`);
        }
    }
}
exports.Property = Property;
//# sourceMappingURL=property.js.map