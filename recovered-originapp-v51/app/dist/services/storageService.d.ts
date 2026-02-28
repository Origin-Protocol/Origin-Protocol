import multer from 'multer';
type StoredVideo = {
    videoUrl: string;
    contentHandle: string;
};
export declare function createVideoUploadMulter(): multer.Multer;
export declare function persistUploadedVideo(file: Express.Multer.File): Promise<StoredVideo>;
export declare function deleteUploadedVideo(videoUrl: string): Promise<void>;
export declare function getStorageDriverSummary(): string;
export {};
//# sourceMappingURL=storageService.d.ts.map