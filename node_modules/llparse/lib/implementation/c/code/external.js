"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.External = void 0;
const base_1 = require("./base");
class External extends base_1.Code {
    build(ctx, out) {
        out.push(`int ${this.ref.name}(`);
        out.push(`    ${ctx.prefix}_t* s, const unsigned char* p,`);
        if (this.ref.signature === 'value') {
            out.push('    const unsigned char* endp,');
            out.push('    int value);');
        }
        else {
            out.push('    const unsigned char* endp);');
        }
    }
}
exports.External = External;
//# sourceMappingURL=external.js.map