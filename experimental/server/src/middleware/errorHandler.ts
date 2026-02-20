import { Request, Response, NextFunction } from 'express';

/**
 * Central error handler — catches anything thrown/passed via next(err).
 */
export function errorHandler(
  err: unknown,
  _req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _next: NextFunction
): void {
  const message = err instanceof Error ? err.message : 'Internal server error';
  const status =
    err instanceof HttpError ? err.statusCode : 500;

  if (status >= 500) {
    console.error('[error]', err);
  }

  res.status(status).json({ error: message });
}

export class HttpError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string
  ) {
    super(message);
    this.name = 'HttpError';
  }
}
