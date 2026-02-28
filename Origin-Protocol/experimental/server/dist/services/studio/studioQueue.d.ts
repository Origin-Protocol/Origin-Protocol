import { StudioFeatureKey, StudioJob, StudioJobStatus } from '../../types/studio';
export declare const studioQueue: {
    enqueue(params: {
        userId: string;
        kind: "generate" | "edit";
        tier: "free" | "paid";
        feature?: StudioFeatureKey;
        mediaKey?: string;
        prompt?: string;
        editType?: "motion" | "stylization" | "re_timing";
        options?: Record<string, unknown>;
    }): StudioJob;
    getById(id: string): StudioJob | null;
    listByUser(userId: string, status?: StudioJobStatus): StudioJob[];
    cancel(userId: string, id: string): StudioJob | null;
};
//# sourceMappingURL=studioQueue.d.ts.map