"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createVideoUploadMulter = createVideoUploadMulter;
exports.persistUploadedVideo = persistUploadedVideo;
exports.deleteUploadedVideo = deleteUploadedVideo;
exports.getStorageDriverSummary = getStorageDriverSummary;
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const node_crypto_1 = __importDefault(require("node:crypto"));
const multer_1 = __importDefault(require("multer"));
const uuid_1 = require("uuid");
const config_1 = require("../config");
const errorHandler_1 = require("../middleware/errorHandler");
const MAX_VIDEO_SIZE_BYTES = 500 * 1024 * 1024;
const ALLOWED_MIME_TYPES = new Set(['video/mp4', 'video/quicktime', 'video/webm']);
function getExt(originalName, mimeType) {
    const fromName = node_path_1.default.extname(originalName || '').toLowerCase();
    if (fromName)
        return fromName;
    if (mimeType === 'video/quicktime')
        return '.mov';
    if (mimeType === 'video/webm')
        return '.webm';
    return '.mp4';
}
function ensureLocalUploadDir() {
    const uploadsDir = node_path_1.default.resolve(config_1.config.storage.localDir);
    if (!node_fs_1.default.existsSync(uploadsDir)) {
        node_fs_1.default.mkdirSync(uploadsDir, { recursive: true });
    }
}
function createLocalDiskStorage() {
    return multer_1.default.diskStorage({
        destination: (_req, _file, cb) => {
            try {
                ensureLocalUploadDir();
                cb(null, config_1.config.storage.localDir);
            }
            catch (error) {
                cb(error, config_1.config.storage.localDir);
            }
        },
        filename: (_req, file, cb) => {
            const ext = getExt(file.originalname, file.mimetype);
            cb(null, `${(0, uuid_1.v4)()}${ext}`);
        },
    });
}
async function computeFileSha256(filePath) {
    const hash = node_crypto_1.default.createHash('sha256');
    await new Promise((resolve, reject) => {
        const stream = node_fs_1.default.createReadStream(filePath);
        stream.on('error', reject);
        stream.on('data', (chunk) => hash.update(chunk));
        stream.on('end', () => resolve());
    });
    return hash.digest('hex');
}
function createVideoUploadMulter() {
    return (0, multer_1.default)({
        storage: createLocalDiskStorage(),
        limits: { fileSize: MAX_VIDEO_SIZE_BYTES },
        fileFilter: (_req, file, cb) => {
            cb(null, ALLOWED_MIME_TYPES.has(file.mimetype));
        },
    });
}
async function persistUploadedVideo(file) {
    if (config_1.config.storage.driver !== 'local') {
        throw new errorHandler_1.HttpError(501, 'S3 upload adapter scaffolded but not enabled yet. Use STORAGE_DRIVER=local for now.');
    }
    if (!file.filename)
        throw new errorHandler_1.HttpError(500, 'Local upload did not produce a filename');
    const localPath = file.path || node_path_1.default.resolve(config_1.config.storage.localDir, file.filename);
    const contentHash = await computeFileSha256(localPath);
    return {
        videoUrl: `/uploads/${file.filename}`,
        contentHandle: contentHash,
    };
}
async function deleteUploadedVideo(videoUrl) {
    if (!videoUrl)
        return;
    if (config_1.config.storage.driver !== 'local') {
        return;
    }
    if (!videoUrl.startsWith('/uploads/'))
        return;
    const filename = videoUrl.slice('/uploads/'.length);
    const target = node_path_1.default.resolve(config_1.config.storage.localDir, filename);
    try {
        await node_fs_1.default.promises.unlink(target);
    }
    catch {
        // Ignore cleanup failures.
    }
}
function getStorageDriverSummary() {
    if (config_1.config.storage.driver === 'local') {
        return `local (${config_1.config.storage.localDir})`;
    }
    const endpoint = config_1.config.storage.s3.endpoint?.trim();
    const endpointLabel = endpoint ? ` via ${endpoint}` : '';
    return `s3 scaffold (${config_1.config.storage.s3.bucket || 'bucket-unset'}${endpointLabel})`;
}
//# sourceMappingURL=storageService.js.map