"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Empty = void 0;
const base_1 = require("./base");
class Empty extends base_1.Node {
    doBuild(out) {
        const otherwise = this.ref.otherwise;
        if (!otherwise.noAdvance) {
            this.prologue(out);
        }
        this.tailTo(out, otherwise);
    }
}
exports.Empty = Empty;
//# sourceMappingURL=empty.js.map