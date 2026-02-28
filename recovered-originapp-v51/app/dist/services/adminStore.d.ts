export type ToolVersion = {
    id: string;
    version: string;
    notes?: string;
    fileName?: string;
    isLatest: boolean;
    forceUpdate: boolean;
    downloadCount: number;
    createdAt: string;
};
export type UsageEvent = {
    id: string;
    metric: string;
    value: number;
    createdAt: string;
    userId?: string;
    source?: string;
};
export type AdminErrorLog = {
    id: string;
    source: string;
    message: string;
    level: 'warning' | 'error';
    createdAt: string;
    meta?: string;
};
export type ModerationReport = {
    id: string;
    videoId: string;
    reporterUserId: string;
    reason: string;
    notes?: string;
    status: 'open' | 'resolved';
    createdAt: string;
    resolvedAt?: string;
    resolvedByUserId?: string;
};
export type PayoutThresholds = {
    minMonthlyNetProfit: number;
    minMonthlyRevenue: number;
    minActiveMonthlyUsers: number;
    minActiveCreators: number;
    minMonthlyApiVerifications: number;
};
export type PayoutPercentages = {
    subscriptionRevenuePct: number;
    apiUsageRevenuePct: number;
    boostRevenuePct: number;
    monthlyProfitPct: number;
};
export type CreatorPayoutConfig = {
    enabled: boolean;
    thresholds: PayoutThresholds;
    percentages: PayoutPercentages;
};
export type PayoutCreatorRow = {
    creatorId: string;
    eligibleViews: number;
    estimatedPayout: number;
};
export type PayoutRun = {
    id: string;
    monthKey: string;
    createdAt: string;
    inputs: {
        totalRevenue: number;
        infrastructureCost: number;
        operatingCost: number;
        subscriptionRevenue: number;
        apiUsageRevenue: number;
        boostRevenue: number;
        activeMonthlyUsers: number;
        activeCreators: number;
        monthlyApiVerifications: number;
    };
    computed: {
        netProfit: number;
        contributions: {
            subscriptions: number;
            apiUsage: number;
            boosts: number;
            profitShare: number;
        };
        creatorPoolBeforeDistribution: number;
        payoutPerView: number;
        totalEligibleViews: number;
        distributedTotal: number;
        rolloverToNextMonth: number;
        activation: {
            globallyEnabled: boolean;
            financialThresholdMet: boolean;
            userbaseThresholdMet: boolean;
            usageThresholdMet: boolean;
            payoutsActive: boolean;
            reason: string;
        };
    };
    creators: PayoutCreatorRow[];
};
export type FlaggedAccount = {
    userId: string;
    reason: string;
    status: 'open' | 'reviewed' | 'cleared';
    createdAt: string;
    updatedAt: string;
};
export type RecommendationWeights = {
    interest: number;
    community: number;
    provenance: number;
    health: number;
    equity: number;
};
export type RecommendationConfig = {
    weights: RecommendationWeights;
    fairnessRotationFrequency: number;
    creatorDominanceCap: number;
    spotlightBoostVisibility: number;
    healthDownrankThreshold: number;
    aiAdaptiveEnabled: boolean;
};
export declare const adminStore: {
    listToolVersions(): ToolVersion[];
    createToolVersion(input: {
        version: string;
        notes?: string;
        fileName?: string;
        isLatest?: boolean;
        forceUpdate?: boolean;
    }): ToolVersion;
    updateToolVersion(versionId: string, updates: {
        isLatest?: boolean;
        forceUpdate?: boolean;
    }): ToolVersion | null;
    incrementToolVersionDownload(versionId: string): ToolVersion | null;
    appendUsageEvent(input: {
        metric: string;
        value?: number;
        userId?: string;
        source?: string;
    }): UsageEvent;
    listUsageEvents(limit?: number): UsageEvent[];
    appendErrorLog(input: {
        source: string;
        message: string;
        level?: "warning" | "error";
        meta?: string;
    }): AdminErrorLog;
    listErrorLogs(limit?: number): AdminErrorLog[];
    listReports(status?: "open" | "resolved" | "all", limit?: number): ModerationReport[];
    createReport(input: {
        videoId: string;
        reporterUserId: string;
        reason: string;
        notes?: string;
    }): ModerationReport;
    resolveReport(reportId: string, resolvedByUserId: string): ModerationReport | null;
    isUserBanned(userId: string): boolean;
    listBannedUserIds(): string[];
    isPromotedAdmin(userId: string): boolean;
    listPromotedAdminUserIds(): string[];
    setPromotedAdmin(userId: string, active: boolean): boolean;
    setUserBan(userId: string, banned: boolean): boolean;
    getPayoutConfig(): CreatorPayoutConfig;
    updatePayoutConfig(input: {
        enabled?: boolean;
        thresholds?: Partial<PayoutThresholds>;
        percentages?: Partial<PayoutPercentages>;
    }): CreatorPayoutConfig;
    listPayoutRuns(limit?: number): PayoutRun[];
    getLatestPayoutRun(): PayoutRun | null;
    appendPayoutRun(run: Omit<PayoutRun, "id" | "createdAt">): PayoutRun;
    listFlaggedAccounts(status?: "open" | "reviewed" | "cleared" | "all", limit?: number): FlaggedAccount[];
    upsertFlaggedAccount(input: {
        userId: string;
        reason: string;
        status?: FlaggedAccount["status"];
    }): FlaggedAccount;
    isCreatorFlagged(userId: string): boolean;
    getRecommendationConfig(): RecommendationConfig;
    updateRecommendationConfig(input: {
        weights?: Partial<RecommendationWeights>;
        fairnessRotationFrequency?: number;
        creatorDominanceCap?: number;
        spotlightBoostVisibility?: number;
        healthDownrankThreshold?: number;
        aiAdaptiveEnabled?: boolean;
    }): RecommendationConfig;
};
//# sourceMappingURL=adminStore.d.ts.map