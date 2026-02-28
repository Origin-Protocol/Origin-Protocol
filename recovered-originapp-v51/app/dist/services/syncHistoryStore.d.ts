export type SyncHistoryStatus = 'success' | 'failed';
export type SyncHistoryItem = {
    id: string;
    userId: string;
    createdAt: string;
    status: SyncHistoryStatus;
    title: string;
    videoUrl: string;
    videoId?: string;
    message?: string;
    payloadJson: string;
};
export declare const syncHistoryStore: {
    listByUser(userId: string): SyncHistoryItem[];
    append(entry: Omit<SyncHistoryItem, "id" | "createdAt">): SyncHistoryItem[];
    clearByUser(userId: string): void;
};
//# sourceMappingURL=syncHistoryStore.d.ts.map