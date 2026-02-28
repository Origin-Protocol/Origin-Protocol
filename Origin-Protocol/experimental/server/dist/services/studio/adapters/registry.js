"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.studioAdapterRegistry = void 0;
const cogVideoXAdapter_1 = require("./cogVideoXAdapter");
const hunyuanVideoAdapter_1 = require("./hunyuanVideoAdapter");
const animateDiffAdapter_1 = require("./animateDiffAdapter");
// Central adapter registry. Extend this map when new providers/models are introduced.
const adapters = new Map([
    ['cogvideox', new cogVideoXAdapter_1.CogVideoXAdapter()],
    ['hunyuan_video', new hunyuanVideoAdapter_1.HunyuanVideoAdapter()],
    ['animatediff', new animateDiffAdapter_1.AnimateDiffAdapter()],
]);
exports.studioAdapterRegistry = {
    get(model) {
        const adapter = adapters.get(model);
        if (!adapter) {
            throw new Error(`No Studio adapter registered for model: ${model}`);
        }
        return adapter;
    },
};
//# sourceMappingURL=registry.js.map