"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Invoke = void 0;
const assert = require("assert");
const edge_1 = require("../edge");
const base_1 = require("./base");
/**
 * This node invokes either external callback or intrinsic code and passes the
 * execution to either a target from a `map` (if the return code matches one of
 * registered in it), or to `otherwise` node.
 */
class Invoke extends base_1.Node {
    /**
     * @param code  External callback or intrinsic code. Can be created with
     *              `builder.code.*()` methods.
     * @param map   Map from callback return codes to target nodes
     */
    constructor(code, map) {
        super('invoke_' + code.name);
        this.code = code;
        Object.keys(map).forEach((mapKey) => {
            const numKey = parseInt(mapKey, 10);
            const targetNode = map[numKey];
            assert.strictEqual(numKey, numKey | 0, 'Invoke\'s map keys must be integers');
            this.addEdge(new edge_1.Edge(targetNode, true, numKey, undefined));
        });
    }
}
exports.Invoke = Invoke;
//# sourceMappingURL=invoke.js.map