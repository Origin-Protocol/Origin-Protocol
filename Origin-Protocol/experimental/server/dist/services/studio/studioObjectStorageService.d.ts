export declare const studioObjectStorageService: {
    createUploadTarget(params: {
        userId: string;
        extension?: string;
        mimeType?: string;
    }): {
        mediaKey: string;
        method: "PUT";
        contentType: string;
        signedUrl: string;
        expiresInSeconds: number;
    };
    attachSignedUploadUrl(target: {
        mediaKey: string;
        method: "PUT";
        contentType: string;
        signedUrl: string;
        expiresInSeconds: number;
    }): Promise<typeof target>;
    writeLocalUpload(token: string, body: Buffer): Promise<{
        mediaKey: string;
    }>;
    assertUserCanAccessMediaKey(userId: string, mediaKey: string): void;
    writeObject(params: {
        mediaKey: string;
        body: Buffer;
        contentType: string;
    }): Promise<void>;
    writeJsonObject(params: {
        mediaKey: string;
        payload: unknown;
    }): Promise<void>;
    getDownloadUrl(userId: string, mediaKey: string): Promise<string>;
};
//# sourceMappingURL=studioObjectStorageService.d.ts.map