import { StudioBillingTier, StudioEditType, StudioJobKind, StudioLaunchModel, StudioOutputResolution, StudioQueuePriority } from '../../types/studio';
export type StudioPlanDefinition = {
    tier: StudioBillingTier;
    displayName: string;
    monthlyPriceUsd: number;
    monthlyGenerateLimit: number | 'unlimited';
    monthlyEditLimit: number | 'unlimited';
    watermark: boolean;
    queuePriority: StudioQueuePriority;
    maxResolution: StudioOutputResolution;
    allowedGenerateModels: StudioLaunchModel[];
    allowedEditTypes: StudioEditType[];
};
export declare const STUDIO_PLAN_CATALOG: Record<StudioBillingTier, StudioPlanDefinition>;
export declare const STUDIO_CREDIT_PACKS: readonly [{
    readonly usd: 5;
    readonly credits: 50;
}, {
    readonly usd: 10;
    readonly credits: 120;
}, {
    readonly usd: 20;
    readonly credits: 300;
}];
export declare const STUDIO_CREDIT_COSTS: Record<StudioLaunchModel, number>;
export declare function coerceResolutionForTier(tier: StudioBillingTier, requested?: unknown): StudioOutputResolution;
export declare function defaultDurationForKind(kind: StudioJobKind): number;
//# sourceMappingURL=plans.d.ts.map