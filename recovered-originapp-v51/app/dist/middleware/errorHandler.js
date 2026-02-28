"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HttpError = void 0;
exports.errorHandler = errorHandler;
/**
 * Central error handler — catches anything thrown/passed via next(err).
 */
function errorHandler(err, _req, res, 
// eslint-disable-next-line @typescript-eslint/no-unused-vars
_next) {
    const message = err instanceof Error ? err.message : 'Internal server error';
    const status = err instanceof HttpError ? err.statusCode : 500;
    if (status >= 500) {
        console.error('[error]', err);
    }
    res.status(status).json({ error: message });
}
class HttpError extends Error {
    constructor(statusCode, message) {
        super(message);
        this.statusCode = statusCode;
        this.name = 'HttpError';
    }
}
exports.HttpError = HttpError;
//# sourceMappingURL=errorHandler.js.map