"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Consume = void 0;
const base_1 = require("./base");
/**
 * This node consumes number of characters specified by state's property with
 * name `field` from the input, and forwards execution to `otherwise` node.
 */
class Consume extends base_1.Node {
    /**
     * @param field  State's property name
     */
    constructor(field) {
        super('consume_' + field);
        this.field = field;
        if (/^_/.test(field)) {
            throw new Error(`Can't use internal field in \`consume()\`: "${field}"`);
        }
    }
}
exports.Consume = Consume;
//# sourceMappingURL=consume.js.map