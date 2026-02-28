import { Comment, VideoMeta } from '../types';
export declare function createVideo(input: Omit<VideoMeta, 'createdAt'> & {
    createdAt?: string;
}): Promise<VideoMeta>;
export declare function getVideoAndIncrementView(id: string): Promise<VideoMeta | null>;
export declare function getVideoById(id: string): Promise<VideoMeta | null>;
export declare function deleteVideo(id: string): Promise<void>;
export declare function toggleLike(userId: string, videoId: string): Promise<boolean>;
export declare function listComments(videoId: string): Promise<Comment[]>;
export declare function addComment(videoId: string, authorId: string, text: string): Promise<Comment>;
export declare function listFeed(page: number, pageSize: number): Promise<{
    items: VideoMeta[];
    total: number;
    hasMore: boolean;
}>;
export declare function listVideosByCreator(creatorId: string): Promise<VideoMeta[]>;
export type ProtectedVideoCandidate = {
    id: string;
    creatorId: string;
    title: string;
    originBundleId: string | null;
    description: string | null;
};
export declare function listProtectedVideoCandidates(): Promise<ProtectedVideoCandidate[]>;
export type UserInteractionSignals = {
    likedVideoIds: string[];
    commentedVideoIds: string[];
    preferredCreators: string[];
    topicKeywords: string[];
};
export declare function getUserInteractionSignals(userId: string): Promise<UserInteractionSignals>;
//# sourceMappingURL=videoRepository.d.ts.map