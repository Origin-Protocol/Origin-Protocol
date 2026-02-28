"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.studioObjectStorageService = void 0;
const crypto_1 = require("crypto");
const fs_1 = require("fs");
const path_1 = require("path");
const client_s3_1 = require("@aws-sdk/client-s3");
const s3_request_presigner_1 = require("@aws-sdk/s3-request-presigner");
const config_1 = require("../../config");
const errorHandler_1 = require("../../middleware/errorHandler");
const r2Layout_1 = require("./r2Layout");
const localUploadGrants = new Map();
const DEFAULT_UPLOAD_TTL_SECONDS = 900;
const DEFAULT_DOWNLOAD_TTL_SECONDS = 900;
function isS3Enabled() {
    return config_1.config.storage.driver === 's3';
}
function normalizeLocalTargetPath(mediaKey) {
    const root = (0, path_1.resolve)(config_1.config.storage.localDir);
    const target = (0, path_1.resolve)(root, mediaKey);
    if (!target.startsWith(root)) {
        throw new errorHandler_1.HttpError(400, 'Invalid media key path');
    }
    return target;
}
function sanitizeExtension(extension) {
    const normalized = (extension ?? 'mp4').toLowerCase().replace(/[^a-z0-9]/g, '');
    return normalized || 'mp4';
}
function assertOwnedMediaKey(userId, mediaKey) {
    const tempPrefix = r2Layout_1.studioR2Layout.tempUploadPrefix(userId);
    const userScopePrefix = `${r2Layout_1.studioR2Layout.tempUploadPrefix(userId).split('/uploads/temp/')[0]}/`;
    if (!mediaKey.startsWith(tempPrefix) && !mediaKey.startsWith(userScopePrefix)) {
        throw new errorHandler_1.HttpError(403, 'Media key is outside your studio scope');
    }
}
function createS3Client() {
    const endpoint = config_1.config.storage.s3.endpoint?.trim() || undefined;
    return new client_s3_1.S3Client({
        region: config_1.config.storage.s3.region,
        endpoint,
        forcePathStyle: true,
        credentials: {
            accessKeyId: config_1.config.storage.s3.accessKey,
            secretAccessKey: config_1.config.storage.s3.secretKey,
        },
    });
}
function assertS3Configured() {
    const { bucket, accessKey, secretKey } = config_1.config.storage.s3;
    if (!bucket || !accessKey || !secretKey) {
        throw new errorHandler_1.HttpError(503, 'Studio object storage is not configured on this server');
    }
}
exports.studioObjectStorageService = {
    createUploadTarget(params) {
        const extension = sanitizeExtension(params.extension);
        const uploadId = `${Date.now()}-${(0, crypto_1.randomBytes)(6).toString('hex')}`;
        const mediaKey = `${r2Layout_1.studioR2Layout.tempUploadPrefix(params.userId)}${uploadId}.${extension}`;
        const contentType = params.mimeType?.trim() || 'video/mp4';
        if (isS3Enabled()) {
            assertS3Configured();
            return {
                mediaKey,
                method: 'PUT',
                contentType,
                signedUrl: '',
                expiresInSeconds: DEFAULT_UPLOAD_TTL_SECONDS,
            };
        }
        const token = (0, crypto_1.randomBytes)(18).toString('hex');
        localUploadGrants.set(token, {
            token,
            userId: params.userId,
            mediaKey,
            contentType,
            expiresAt: Date.now() + (DEFAULT_UPLOAD_TTL_SECONDS * 1000),
        });
        return {
            mediaKey,
            method: 'PUT',
            contentType,
            signedUrl: `/api/studio/uploads/local/${token}`,
            expiresInSeconds: DEFAULT_UPLOAD_TTL_SECONDS,
        };
    },
    async attachSignedUploadUrl(target) {
        if (!isS3Enabled()) {
            return target;
        }
        assertS3Configured();
        const client = createS3Client();
        const command = new client_s3_1.PutObjectCommand({
            Bucket: config_1.config.storage.s3.bucket,
            Key: target.mediaKey,
            ContentType: target.contentType,
        });
        const signedUrl = await (0, s3_request_presigner_1.getSignedUrl)(client, command, { expiresIn: target.expiresInSeconds });
        return { ...target, signedUrl };
    },
    async writeLocalUpload(token, body) {
        const grant = localUploadGrants.get(token);
        if (!grant) {
            throw new errorHandler_1.HttpError(404, 'Upload grant not found');
        }
        if (Date.now() > grant.expiresAt) {
            localUploadGrants.delete(token);
            throw new errorHandler_1.HttpError(410, 'Upload grant expired');
        }
        const targetPath = normalizeLocalTargetPath(grant.mediaKey);
        await fs_1.promises.mkdir((0, path_1.dirname)(targetPath), { recursive: true });
        await fs_1.promises.writeFile(targetPath, body);
        localUploadGrants.delete(token);
        return { mediaKey: grant.mediaKey };
    },
    assertUserCanAccessMediaKey(userId, mediaKey) {
        assertOwnedMediaKey(userId, mediaKey);
    },
    async writeObject(params) {
        if (!isS3Enabled()) {
            const targetPath = normalizeLocalTargetPath(params.mediaKey);
            await fs_1.promises.mkdir((0, path_1.dirname)(targetPath), { recursive: true });
            await fs_1.promises.writeFile(targetPath, params.body);
            return;
        }
        assertS3Configured();
        const client = createS3Client();
        await client.send(new client_s3_1.PutObjectCommand({
            Bucket: config_1.config.storage.s3.bucket,
            Key: params.mediaKey,
            Body: params.body,
            ContentType: params.contentType,
        }));
    },
    async writeJsonObject(params) {
        await this.writeObject({
            mediaKey: params.mediaKey,
            body: Buffer.from(JSON.stringify(params.payload, null, 2), 'utf8'),
            contentType: 'application/json',
        });
    },
    async getDownloadUrl(userId, mediaKey) {
        assertOwnedMediaKey(userId, mediaKey);
        if (!isS3Enabled()) {
            return `/uploads/${encodeURI(mediaKey)}`;
        }
        assertS3Configured();
        const client = createS3Client();
        const command = new client_s3_1.GetObjectCommand({
            Bucket: config_1.config.storage.s3.bucket,
            Key: mediaKey,
        });
        return (0, s3_request_presigner_1.getSignedUrl)(client, command, { expiresIn: DEFAULT_DOWNLOAD_TTL_SECONDS });
    },
};
//# sourceMappingURL=studioObjectStorageService.js.map