import { StudioAdapterResult } from '../../../types/studio';
export declare function runRemoteStudioInference(params: {
    endpoint: string;
    adapterName: string;
    payload: Record<string, unknown>;
    fallbackDurationSeconds: number;
    fallbackCostUsd: number;
}): Promise<StudioAdapterResult | null>;
//# sourceMappingURL=inferenceGateway.d.ts.map