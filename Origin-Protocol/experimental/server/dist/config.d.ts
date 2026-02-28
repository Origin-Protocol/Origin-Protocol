export declare const config: {
    readonly port: number;
    readonly nodeEnv: string;
    readonly database: {
        readonly usePrisma: boolean;
    };
    readonly jwt: {
        readonly secret: string;
        readonly expiresIn: string;
    };
    readonly origin: {
        readonly ledgerUrl: string;
        readonly platformId: string;
    };
    readonly ingest: {
        readonly apiKey: string;
    };
    readonly cloudflareStream: {
        readonly apiToken: string;
        readonly accountId: string;
        readonly subdomain: string;
    };
    readonly moderation: {
        readonly cloudflareApiUrl: string;
        readonly cloudflareApiToken: string;
        readonly cloudflareAccountId: string;
        readonly cloudflareModel: string;
        readonly timeoutMs: number;
        readonly retries: number;
        readonly blockedKeywords: string[];
    };
    readonly storage: {
        readonly driver: "local" | "s3";
        readonly localDir: string;
        readonly s3: {
            readonly bucket: string;
            readonly region: string;
            readonly accessKey: string;
            readonly secretKey: string;
            readonly endpoint: string;
        };
    };
    readonly membership: {
        readonly stripeSecretKey: string;
        readonly stripePublishableKey: string;
        readonly stripeWebhookSecret: string;
        readonly stripePriceId: string;
        readonly stripePriceLookupKey: string;
        readonly stripeDefaultCreatorProductId: string;
        readonly stripeMeterId: string;
        readonly stripeMeterEventName: string;
        readonly frontendBaseUrl: string;
        readonly stripeSuccessUrl: string;
        readonly stripeCancelUrl: string;
        readonly adminEmails: string[];
    };
    readonly studio: {
        readonly workerAuthToken: string;
        readonly workers: {
            readonly cogVideoXUrl: string;
            readonly hunyuanVideoUrl: string;
            readonly animateDiffUrl: string;
        };
    };
    readonly abigail: {
        readonly tenantId: string;
        readonly apiKey: string;
        readonly maxRetentionDays: number;
        readonly hardDeleteGraceDays: number;
        readonly minImportanceToStore: number;
        readonly blockedSensitiveKeywords: string[];
        readonly anonymizationSalt: string;
    };
};
export declare function assertRuntimeConfig(): void;
//# sourceMappingURL=config.d.ts.map