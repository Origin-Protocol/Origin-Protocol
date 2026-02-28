export type StudioPhase = 'phase1' | 'phase2' | 'phase3';
export type StudioFeatureKey = 'trim' | 'captions' | 'filters' | 'templates' | 'auto_edit' | 'auto_caption_whisper' | 'noise_remove' | 'smart_crop' | 'thumbnail_generate' | 'text_to_video' | 'describe_to_animate' | 'ai_dialogue' | 'ai_voice_acting' | 'lip_sync' | 'character_consistency';
export type StudioFeatureKind = 'basic' | 'assist' | 'generate';
export type StudioProvider = 'local' | 'openai' | 'runway' | 'pika' | 'luma' | 'elevenlabs' | 'demucs' | 'rnnoise' | 'cogvideox' | 'hunyuan_video' | 'animatediff';
export type StudioLaunchModel = 'cogvideox' | 'hunyuan_video' | 'animatediff';
export type StudioJobKind = 'generate' | 'edit';
export type StudioEditType = 'motion' | 'stylization' | 're_timing';
export type StudioTier = 'free' | 'paid' | 'creator' | 'pro' | 'enterprise';
export type StudioBillingTier = 'free' | 'paid';
export type StudioOutputResolution = '720p' | '1080p' | '4k';
export type StudioQueuePriority = 'low' | 'high';
export type StudioJobStatus = 'queued' | 'running' | 'succeeded' | 'failed' | 'canceled';
export type StudioFeatureDefinition = {
    key: StudioFeatureKey;
    label: string;
    phase: StudioPhase;
    kind: StudioFeatureKind;
    providers: StudioProvider[];
    estimateSeconds: number;
    billableCredits: number;
};
export type StudioJob = {
    id: string;
    userId: string;
    kind: StudioJobKind;
    feature: StudioFeatureKey;
    phase: StudioPhase;
    provider: StudioProvider;
    model: StudioLaunchModel;
    tier: StudioBillingTier;
    editType?: StudioEditType;
    status: StudioJobStatus;
    progress: number;
    step: string;
    createdAt: string;
    startedAt?: string;
    finishedAt?: string;
    error?: string;
    input: {
        mediaKey?: string;
        prompt?: string;
        options?: Record<string, unknown>;
    };
    output?: {
        mediaKey: string;
        manifestKey: string;
        downloadUrl: string;
        metadata: {
            modelUsed: StudioLaunchModel;
            tierUsed: StudioBillingTier;
            durationSeconds: number;
            costEstimateUsd: number;
            queuePriority: StudioQueuePriority;
            watermarked: boolean;
            resolution: StudioOutputResolution;
        };
    };
};
export type StudioUnifiedJobStatus = {
    id: string;
    status: StudioJobStatus;
    progress: number;
    step: string;
    kind: StudioJobKind;
    tier: StudioBillingTier;
    model: StudioLaunchModel;
    createdAt: string;
    startedAt?: string;
    finishedAt?: string;
    error?: string;
    input: {
        prompt?: string;
        mediaKey?: string;
        editType?: StudioEditType;
    };
    output?: {
        mediaKey: string;
        manifestKey: string;
        downloadUrl: string;
        metadata: NonNullable<StudioJob['output']>['metadata'];
    };
};
export type StudioCredits = {
    tier: StudioTier;
    remaining: number;
    reserved: number;
    monthlyLimit: number;
};
export type StudioAdapterInput = {
    userId: string;
    jobId: string;
    kind: StudioJobKind;
    tier: StudioBillingTier;
    model: StudioLaunchModel;
    prompt?: string;
    mediaKey?: string;
    editType?: StudioEditType;
    options?: Record<string, unknown>;
};
export type StudioAdapterResult = {
    outputBuffer: Buffer;
    outputMimeType: string;
    outputExtension: string;
    durationSeconds: number;
    estimatedCostUsd: number;
    trace: {
        adapter: string;
        inferenceMs: number;
        notes: string[];
    };
};
//# sourceMappingURL=studio.d.ts.map