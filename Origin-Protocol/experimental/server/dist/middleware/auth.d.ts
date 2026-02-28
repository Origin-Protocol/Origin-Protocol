import { Request, Response, NextFunction } from 'express';
export interface AuthRequest extends Request {
    userId?: string;
}
/**
 * Verifies the Bearer JWT in the Authorization header and attaches
 * the decoded `userId` to the request object.
 */
export declare function requireAuth(req: AuthRequest, res: Response, next: NextFunction): void;
//# sourceMappingURL=auth.d.ts.map