type DirectUploadResult = {
    uid: string;
    uploadURL: string;
};
type StreamDetailsResult = {
    uid: string;
    readyToStream?: boolean;
    duration?: number;
};
export declare const cloudflareStreamService: {
    isConfigured(): boolean;
    createDirectUpload(params: {
        creatorId: string;
        title: string;
    }): Promise<DirectUploadResult>;
    getStreamDetails(uid: string): Promise<StreamDetailsResult>;
    buildPlaybackUrl(uid: string): string;
    buildThumbnailUrl(uid: string): string;
};
export {};
//# sourceMappingURL=cloudflareStreamService.d.ts.map