export interface User {
    id: string;
    username: string;
    email: string;
    displayName: string;
    avatarUrl: string | null;
    bio: string | null;
    creatorKeyId: string | null;
    createdAt: string;
}
export interface VideoMeta {
    id: string;
    creatorId: string;
    creatorDisplayName?: string;
    creatorUsername?: string;
    creatorAvatarUrl?: string | null;
    title: string;
    description: string | null;
    videoUrl: string;
    thumbnailUrl: string | null;
    duration: number | null;
    likeCount: number;
    commentCount: number;
    viewCount: number;
    originBundleId: string | null;
    originVerified: boolean;
    originReasons?: OriginReason[];
    originVerificationCheckedAt?: string | null;
    createdAt: string;
}
export interface Comment {
    id: string;
    videoId: string;
    authorId: string;
    authorDisplayName?: string;
    authorUsername?: string;
    text: string;
    createdAt: string;
}
export interface OriginVerifyResult {
    ok: boolean;
    reasons: OriginReason[];
}
export interface OriginReason {
    code: string;
    severity: string;
    message: string;
    platformAction: string;
    creatorAction: string;
}
export interface PaginatedResponse<T> {
    items: T[];
    total: number;
    page: number;
    pageSize: number;
    hasMore: boolean;
}
export interface RegisterBody {
    username: string;
    email: string;
    password: string;
    displayName?: string;
}
export interface LoginBody {
    email: string;
    password: string;
}
export interface UploadVideoBody {
    title: string;
    description?: string;
    originBundleId?: string;
    assetId?: string;
    keyId?: string;
    contentHash?: string;
    originId?: string;
    protectedUpload?: boolean;
}
export interface PostCommentBody {
    text: string;
}
export interface UpdateProfileBody {
    username?: string;
    displayName?: string;
    bio?: string;
    avatarUrl?: string | null;
    creatorKeyId?: string | null;
}
//# sourceMappingURL=index.d.ts.map