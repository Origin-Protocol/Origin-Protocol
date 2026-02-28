type BuildPathsInput = {
    userId: string;
    jobId: string;
    feature: string;
    extension?: string;
};
export declare const STUDIO_BUCKET_PREFIX = "origin-studio";
export declare const studioR2Layout: {
    inputKey({ userId, jobId, extension }: BuildPathsInput): string;
    outputKey({ userId, jobId, feature, extension }: BuildPathsInput): string;
    manifestKey({ userId, jobId }: BuildPathsInput): string;
    tempUploadPrefix(userId: string): string;
};
export {};
//# sourceMappingURL=r2Layout.d.ts.map