import { StudioBillingTier, StudioEditType, StudioJobKind, StudioLaunchModel } from '../../../types/studio';
export type StudioRoutingDecision = {
    tier: StudioBillingTier;
    kind: StudioJobKind;
    model: StudioLaunchModel;
    editType?: StudioEditType;
    reason: string;
};
export declare function routeStudioModel(params: {
    tier: StudioBillingTier;
    kind: StudioJobKind;
    editType?: StudioEditType;
}): StudioRoutingDecision;
//# sourceMappingURL=modelRouter.d.ts.map