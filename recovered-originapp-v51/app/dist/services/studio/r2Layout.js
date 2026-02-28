"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.studioR2Layout = exports.STUDIO_BUCKET_PREFIX = void 0;
exports.STUDIO_BUCKET_PREFIX = 'origin-studio';
exports.studioR2Layout = {
    inputKey({ userId, jobId, extension = 'mp4' }) {
        return `${exports.STUDIO_BUCKET_PREFIX}/users/${userId}/jobs/${jobId}/input/source.${extension}`;
    },
    outputKey({ userId, jobId, feature, extension = 'mp4' }) {
        return `${exports.STUDIO_BUCKET_PREFIX}/users/${userId}/jobs/${jobId}/output/${feature}.${extension}`;
    },
    manifestKey({ userId, jobId }) {
        return `${exports.STUDIO_BUCKET_PREFIX}/users/${userId}/jobs/${jobId}/manifest/job.json`;
    },
    tempUploadPrefix(userId) {
        return `${exports.STUDIO_BUCKET_PREFIX}/users/${userId}/uploads/temp/`;
    },
};
//# sourceMappingURL=r2Layout.js.map