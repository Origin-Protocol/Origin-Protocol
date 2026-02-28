export type LiveSessionStatus = 'live' | 'ended';
export type LiveSessionRecord = {
    id: string;
    hostUserId: string;
    title: string;
    description: string | null;
    status: LiveSessionStatus;
    startedAt: string;
    endedAt: string | null;
    viewerIds: string[];
    peakViewerCount: number;
};
export type LiveCommentRecord = {
    id: string;
    sessionId: string;
    authorId: string;
    parentId: string | null;
    text: string;
    createdAt: string;
};
export declare class LiveStore {
    private sessions;
    private comments;
    private sessionLikes;
    private commentLikes;
    constructor();
    private flush;
    createSession(input: {
        hostUserId: string;
        title: string;
        description?: string | null;
    }): LiveSessionRecord;
    getSession(sessionId: string): LiveSessionRecord | null;
    listSessions(status?: 'live' | 'ended' | 'all', limit?: number): LiveSessionRecord[];
    findLiveSessionByHost(hostUserId: string): LiveSessionRecord | null;
    endSession(sessionId: string): LiveSessionRecord | null;
    setViewerPresence(sessionId: string, userId: string, active: boolean): LiveSessionRecord | null;
    createComment(input: {
        sessionId: string;
        authorId: string;
        text: string;
        parentId?: string | null;
    }): LiveCommentRecord;
    getComment(commentId: string): LiveCommentRecord | null;
    listComments(sessionId: string): LiveCommentRecord[];
    toggleSessionLike(sessionId: string, userId: string): boolean;
    toggleCommentLike(commentId: string, userId: string): boolean;
    countSessionLikes(sessionId: string): number;
    hasUserLikedSession(sessionId: string, userId: string): boolean;
    countCommentLikes(commentId: string): number;
    hasUserLikedComment(commentId: string, userId: string): boolean;
}
export declare const liveStore: LiveStore;
//# sourceMappingURL=liveStore.d.ts.map