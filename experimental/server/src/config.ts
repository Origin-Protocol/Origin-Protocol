import * as dotenv from 'dotenv';
dotenv.config();

export const config = {
  port: parseInt(process.env.PORT ?? '4000', 10),
  nodeEnv: process.env.NODE_ENV ?? 'development',

  jwt: {
    secret: process.env.JWT_SECRET ?? 'change-me-in-production',
    expiresIn: process.env.JWT_EXPIRES_IN ?? '7d',
  },

  origin: {
    ledgerUrl: process.env.ORIGIN_LEDGER_URL ?? 'http://127.0.0.1:9050',
    platformId: process.env.ORIGIN_PLATFORM_ID ?? 'origin-social',
  },

  storage: {
    driver: (process.env.STORAGE_DRIVER ?? 'local') as 'local' | 's3',
    localDir: process.env.STORAGE_LOCAL_DIR ?? './uploads',
    s3: {
      bucket: process.env.S3_BUCKET ?? '',
      region: process.env.S3_REGION ?? 'us-east-1',
      accessKey: process.env.S3_ACCESS_KEY ?? '',
      secretKey: process.env.S3_SECRET_KEY ?? '',
    },
  },
} as const;
