"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Trie = exports.TrieSingle = exports.TrieSequence = exports.TrieNode = exports.TrieEmpty = void 0;
const assert = require("assert");
const buffer_1 = require("buffer");
const empty_1 = require("./empty");
Object.defineProperty(exports, "TrieEmpty", { enumerable: true, get: function () { return empty_1.TrieEmpty; } });
const node_1 = require("./node");
Object.defineProperty(exports, "TrieNode", { enumerable: true, get: function () { return node_1.TrieNode; } });
const sequence_1 = require("./sequence");
Object.defineProperty(exports, "TrieSequence", { enumerable: true, get: function () { return sequence_1.TrieSequence; } });
const single_1 = require("./single");
Object.defineProperty(exports, "TrieSingle", { enumerable: true, get: function () { return single_1.TrieSingle; } });
class Trie {
    constructor(name) {
        this.name = name;
    }
    build(edges) {
        if (edges.length === 0) {
            return undefined;
        }
        const internalEdges = [];
        for (const edge of edges) {
            internalEdges.push({
                key: edge.key,
                noAdvance: edge.noAdvance,
                node: edge.node,
                value: edge.value,
            });
        }
        return this.level(internalEdges, []);
    }
    level(edges, path) {
        const first = edges[0].key;
        const last = edges[edges.length - 1].key;
        // Leaf
        if (edges.length === 1 && edges[0].key.length === 0) {
            return new empty_1.TrieEmpty(edges[0].node, edges[0].value);
        }
        // Find the longest common sub-string
        let common = 0;
        for (; common < first.length; common++) {
            if (first[common] !== last[common]) {
                break;
            }
        }
        // Sequence
        if (common > 1) {
            return this.sequence(edges, first.slice(0, common), path);
        }
        // Single
        return this.single(edges, path);
    }
    slice(edges, off) {
        return edges.map((edge) => {
            return {
                key: edge.key.slice(off),
                noAdvance: edge.noAdvance,
                node: edge.node,
                value: edge.value,
            };
        }).sort((a, b) => {
            return a.key.compare(b.key);
        });
    }
    sequence(edges, prefix, path) {
        const sliced = this.slice(edges, prefix.length);
        const noAdvance = sliced.some((edge) => edge.noAdvance);
        assert(!noAdvance);
        const child = this.level(sliced, path.concat(prefix));
        return new sequence_1.TrieSequence(prefix, child);
    }
    single(edges, path) {
        // Check for duplicates
        if (edges[0].key.length === 0) {
            assert(path.length !== 0, `Empty root entry at "${this.name}"`);
            assert(edges.length === 1 || edges[1].key.length !== 0, `Duplicate entries in "${this.name}" at [ ${path.join(', ')} ]`);
        }
        let otherwise;
        const keys = new Map();
        for (const edge of edges) {
            if (edge.key.length === 0) {
                otherwise = new empty_1.TrieEmpty(edge.node, edge.value);
                continue;
            }
            const key = edge.key[0];
            if (keys.has(key)) {
                keys.get(key).push(edge);
            }
            else {
                keys.set(key, [edge]);
            }
        }
        const children = [];
        keys.forEach((subEdges, key) => {
            const sliced = this.slice(subEdges, 1);
            const subpath = path.concat(buffer_1.Buffer.from([key]));
            const noAdvance = subEdges.some((edge) => edge.noAdvance);
            const allSame = subEdges.every((edge) => edge.noAdvance === noAdvance);
            assert(allSame || subEdges.length === 0, 'Conflicting `.peek()` and `.match()` entries in ' +
                `"${this.name}" at [ ${subpath.join(', ')} ]`);
            children.push({
                key,
                noAdvance,
                node: this.level(sliced, subpath),
            });
        });
        return new single_1.TrieSingle(children, otherwise);
    }
}
exports.Trie = Trie;
//# sourceMappingURL=index.js.map