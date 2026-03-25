"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Sequence = void 0;
const constants_1 = require("../constants");
const base_1 = require("./base");
class Sequence extends base_1.Node {
    doBuild(out) {
        const ctx = this.compilation;
        out.push('llparse_match_t match_seq;');
        out.push('');
        this.prologue(out);
        const matchSequence = ctx.getMatchSequence(this.ref.transform, this.ref.select);
        out.push(`match_seq = ${matchSequence}(${ctx.stateArg()}, ` +
            `${ctx.posArg()}, ` +
            `${ctx.endPosArg()}, ${ctx.blob(this.ref.select)}, ` +
            `${this.ref.select.length});`);
        out.push('p = match_seq.current;');
        let tmp;
        out.push('switch (match_seq.status) {');
        out.push(`  case ${constants_1.SEQUENCE_COMPLETE}: {`);
        tmp = [];
        this.tailTo(tmp, {
            noAdvance: false,
            node: this.ref.edge.node,
            value: this.ref.edge.value,
        });
        ctx.indent(out, tmp, '    ');
        out.push('  }');
        out.push(`  case ${constants_1.SEQUENCE_PAUSE}: {`);
        tmp = [];
        this.pause(tmp);
        ctx.indent(out, tmp, '    ');
        out.push('  }');
        out.push(`  case ${constants_1.SEQUENCE_MISMATCH}: {`);
        tmp = [];
        this.tailTo(tmp, this.ref.otherwise);
        ctx.indent(out, tmp, '    ');
        out.push('  }');
        out.push('}');
    }
}
exports.Sequence = Sequence;
//# sourceMappingURL=sequence.js.map