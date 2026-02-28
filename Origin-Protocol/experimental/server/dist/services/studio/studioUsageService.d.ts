import { StudioBillingTier, StudioJobKind } from '../../types/studio';
type StudioUsageCounter = {
    generate: number;
    edit: number;
};
declare function monthKey(date?: Date): string;
export declare const studioUsageService: {
    monthKey: typeof monthKey;
    getUsage(userId: string, key?: string): StudioUsageCounter;
    getUsageSummary(userId: string, tier: StudioBillingTier, key?: string): {
        monthKey: string;
        tier: StudioBillingTier;
        usage: StudioUsageCounter;
        limits: {
            generate: number | "unlimited";
            edit: number | "unlimited";
        };
        remaining: {
            generate: number | "unlimited";
            edit: number | "unlimited";
        };
    };
    assertWithinLimit(userId: string, tier: StudioBillingTier, kind: StudioJobKind): void;
    recordSuccess(userId: string, kind: StudioJobKind): void;
};
export {};
//# sourceMappingURL=studioUsageService.d.ts.map