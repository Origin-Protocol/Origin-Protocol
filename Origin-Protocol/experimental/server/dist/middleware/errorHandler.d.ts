import { Request, Response, NextFunction } from 'express';
/**
 * Central error handler — catches anything thrown/passed via next(err).
 */
export declare function errorHandler(err: unknown, _req: Request, res: Response, _next: NextFunction): void;
export declare class HttpError extends Error {
    readonly statusCode: number;
    constructor(statusCode: number, message: string);
}
//# sourceMappingURL=errorHandler.d.ts.map