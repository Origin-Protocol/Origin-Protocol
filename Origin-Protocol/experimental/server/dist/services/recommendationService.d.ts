import { VideoMeta } from '../types';
export type FeedType = 'home' | 'community' | 'spotlight' | 'fairness';
type RankedVideo = VideoMeta & {
    recommendation: {
        feedType: FeedType;
        score: number;
        reasons: string[];
        components: {
            interest: number;
            community: number;
            provenance: number;
            health: number;
            equity: number;
        };
    };
};
export declare const recommendationService: {
    rankFeed(userId: string, opts: {
        feedType: FeedType;
        page: number;
        pageSize: number;
    }): Promise<{
        items: RankedVideo[];
        total: number;
        page: number;
        pageSize: number;
        hasMore: boolean;
    }>;
};
export {};
//# sourceMappingURL=recommendationService.d.ts.map