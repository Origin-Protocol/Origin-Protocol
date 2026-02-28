"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.routeStudioModel = routeStudioModel;
function routeStudioModel(params) {
    if (params.kind === 'edit') {
        return {
            tier: params.tier,
            kind: 'edit',
            model: 'animatediff',
            editType: params.editType ?? 'motion',
            reason: 'edit jobs are always routed to AnimateDiff in v1',
        };
    }
    if (params.tier === 'paid') {
        return {
            tier: params.tier,
            kind: 'generate',
            model: 'hunyuan_video',
            reason: 'paid generation jobs route to Hunyuan Video in v1',
        };
    }
    return {
        tier: params.tier,
        kind: 'generate',
        model: 'cogvideox',
        reason: 'free generation jobs route to CogVideoX in v1',
    };
}
//# sourceMappingURL=modelRouter.js.map