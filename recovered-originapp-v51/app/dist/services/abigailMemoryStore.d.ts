export type MemoryType = 'trait' | 'preference' | 'goal' | 'habit' | 'fact' | 'reaction';
export type MemorySource = 'chat' | 'memory_patch' | 'system' | 'manual' | 'import';
export type MemoryCandidate = {
    type: MemoryType;
    key: string;
    value: string;
    summary: string;
    importance: number;
    source: MemorySource;
    confidence?: number;
    tags?: string[];
    expiresAt?: string | null;
    decayPerDay?: number;
};
export type UserPersonalityProfile = {
    userId: string;
    tenantId: string;
    preferredTone?: string;
    pacing?: 'brief' | 'balanced' | 'detailed';
    topics: string[];
    goals: string[];
    traits: string[];
    updatedAt: string;
    deletedAt?: string | null;
};
export type UserMemoryRecord = {
    id: string;
    userId: string;
    tenantId: string;
    type: MemoryType;
    key: string;
    value: string;
    summary: string;
    importance: number;
    confidence: number;
    source: MemorySource;
    tags: string[];
    createdAt: string;
    updatedAt: string;
    lastObservedAt: string;
    expiresAt?: string | null;
    decayPerDay: number;
    softDeletedAt?: string | null;
    hardDeletedAt?: string | null;
};
export type UserMemoryEvent = {
    id: string;
    userId: string;
    tenantId: string;
    eventType: string;
    title: string;
    detail?: string;
    importance: number;
    source: MemorySource;
    createdAt: string;
    softDeletedAt?: string | null;
    hardDeletedAt?: string | null;
};
export type RetrievalResult = {
    profile: UserPersonalityProfile | null;
    memories: Array<UserMemoryRecord & {
        retrievalScore: number;
    }>;
    generatedContext: string[];
};
export type MemoryIngestResult = {
    created: UserMemoryRecord[];
    updated: UserMemoryRecord[];
    skipped: Array<{
        reason: string;
        candidate: MemoryCandidate;
    }>;
    profile: UserPersonalityProfile;
};
type ForgetOptions = {
    type?: MemoryType;
    source?: MemorySource;
    beforeTs?: string;
    anonymize?: boolean;
    hardDelete?: boolean;
};
type MemoryPatchInput = {
    profile_settings?: {
        preferred_tone?: string;
        pacing?: 'brief' | 'balanced' | 'detailed';
        topics?: string[];
        goals?: string[];
        traits?: string[];
    };
    events?: Array<{
        type?: string;
        title?: string;
        detail?: string;
        createdAt?: string;
        importance?: number;
    }>;
    memories?: Array<{
        type?: MemoryType;
        key?: string;
        value?: string;
        summary?: string;
        importance?: number;
        confidence?: number;
        tags?: string[];
        expires_at?: string | null;
    }>;
};
declare class AbigailMemoryStore {
    private readonly profiles;
    private readonly memories;
    private readonly events;
    constructor();
    private flush;
    private isSensitive;
    private isExpired;
    private isActiveMemory;
    private isActiveEvent;
    private getOrCreateProfile;
    private updateProfileFromCandidate;
    private rankCandidateImportance;
    private extractCandidatesFromTurn;
    private upsertMemory;
    applyRetentionPolicy(): void;
    ingestConversationTurn(input: {
        userId: string;
        tenantId: string;
        message: string;
        source?: MemorySource;
        metadata?: Record<string, unknown>;
    }): MemoryIngestResult;
    applyMemoryPatch(input: {
        userId: string;
        tenantId: string;
        patch: MemoryPatchInput;
    }): {
        created: UserMemoryRecord[];
        updated: UserMemoryRecord[];
        eventsAdded: number;
        profile: UserPersonalityProfile;
    };
    retrieveContext(input: {
        userId: string;
        tenantId: string;
        query?: string;
        limit?: number;
    }): RetrievalResult;
    listSnapshot(input: {
        userId: string;
        tenantId: string;
        limit?: number;
    }): {
        profile: UserPersonalityProfile | null;
        events: UserMemoryEvent[];
        memories: UserMemoryRecord[];
        retentionPolicy: {
            maxRetentionDays: number;
            blockedSensitiveKeywords: string[];
        };
    };
    generateRecommendations(input: {
        userId: string;
        tenantId: string;
    }): Array<{
        id: string;
        kind: 'video' | 'article' | 'task';
        title: string;
        reason: string;
    }>;
    forgetUserData(input: {
        userId: string;
        tenantId: string;
        options?: ForgetOptions;
    }): {
        affectedMemories: number;
        affectedEvents: number;
        profileDeleted: boolean;
    };
    exportUserData(input: {
        userId: string;
        tenantId: string;
    }): {
        profile: UserPersonalityProfile | null;
        memories: UserMemoryRecord[];
        events: UserMemoryEvent[];
        exportedAt: string;
    };
}
export declare const abigailMemoryStore: AbigailMemoryStore;
export {};
//# sourceMappingURL=abigailMemoryStore.d.ts.map