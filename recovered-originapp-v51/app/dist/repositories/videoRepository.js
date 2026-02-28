"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createVideo = createVideo;
exports.getVideoAndIncrementView = getVideoAndIncrementView;
exports.getVideoById = getVideoById;
exports.deleteVideo = deleteVideo;
exports.toggleLike = toggleLike;
exports.listComments = listComments;
exports.addComment = addComment;
exports.listFeed = listFeed;
exports.listVideosByCreator = listVideosByCreator;
exports.listProtectedVideoCandidates = listProtectedVideoCandidates;
exports.getUserInteractionSignals = getUserInteractionSignals;
const uuid_1 = require("uuid");
const config_1 = require("../config");
const store_1 = require("../models/store");
const prisma_1 = require("../models/prisma");
const ORIGIN_VERIFY_MARKER = '[origin_verification]';
function extractOriginVerificationMeta(description) {
    if (!description) {
        return { cleanDescription: description };
    }
    const markerIndex = description.indexOf(ORIGIN_VERIFY_MARKER);
    if (markerIndex < 0) {
        return { cleanDescription: description };
    }
    const cleanDescription = description.slice(0, markerIndex).trimEnd() || null;
    const encoded = description.slice(markerIndex + ORIGIN_VERIFY_MARKER.length).trim();
    if (!encoded) {
        return { cleanDescription };
    }
    try {
        const parsed = JSON.parse(encoded);
        return {
            cleanDescription,
            originReasons: Array.isArray(parsed.reasons) ? parsed.reasons : undefined,
            originVerificationCheckedAt: parsed.checkedAt ?? null,
        };
    }
    catch {
        return { cleanDescription };
    }
}
function toVideoMeta(video) {
    const meta = extractOriginVerificationMeta(video.description);
    return {
        ...video,
        description: meta.cleanDescription,
        originReasons: meta.originReasons,
        originVerificationCheckedAt: meta.originVerificationCheckedAt,
        createdAt: typeof video.createdAt === 'string'
            ? video.createdAt
            : video.createdAt.toISOString(),
    };
}
function toComment(comment) {
    return {
        ...comment,
        createdAt: typeof comment.createdAt === 'string'
            ? comment.createdAt
            : comment.createdAt.toISOString(),
    };
}
async function createVideo(input) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const created = await prisma_1.prisma.video.create({
            data: {
                id: input.id,
                creatorId: input.creatorId,
                title: input.title,
                description: input.description,
                videoUrl: input.videoUrl,
                thumbnailUrl: input.thumbnailUrl,
                duration: input.duration,
                likeCount: input.likeCount,
                commentCount: input.commentCount,
                viewCount: input.viewCount,
                originBundleId: input.originBundleId,
                originVerified: input.originVerified,
            },
        });
        return toVideoMeta(created);
    }
    const createdAt = input.createdAt ?? new Date().toISOString();
    const video = {
        ...input,
        createdAt,
    };
    store_1.db.videos.set(video.id, video);
    return video;
}
async function getVideoAndIncrementView(id) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const video = await prisma_1.prisma.video.findUnique({
            where: { id },
            include: {
                creator: {
                    select: {
                        displayName: true,
                        username: true,
                        avatarUrl: true,
                    },
                },
            },
        });
        if (!video)
            return null;
        const updated = await prisma_1.prisma.video.update({
            where: { id: video.id },
            data: { viewCount: { increment: 1 } },
            include: {
                creator: {
                    select: {
                        displayName: true,
                        username: true,
                        avatarUrl: true,
                    },
                },
            },
        });
        return toVideoMeta({
            ...updated,
            creatorDisplayName: updated.creator.displayName,
            creatorUsername: updated.creator.username,
            creatorAvatarUrl: updated.creator.avatarUrl,
        });
    }
    const video = store_1.db.videos.get(id);
    if (!video)
        return null;
    const updated = { ...video, viewCount: video.viewCount + 1 };
    store_1.db.videos.set(video.id, updated);
    const creator = store_1.db.users.get(updated.creatorId);
    return {
        ...updated,
        creatorDisplayName: creator?.displayName,
        creatorUsername: creator?.username,
        creatorAvatarUrl: creator?.avatarUrl ?? null,
    };
}
async function getVideoById(id) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const video = await prisma_1.prisma.video.findUnique({
            where: { id },
            include: {
                creator: {
                    select: {
                        displayName: true,
                        username: true,
                        avatarUrl: true,
                    },
                },
            },
        });
        if (!video)
            return null;
        return toVideoMeta({
            ...video,
            creatorDisplayName: video.creator.displayName,
            creatorUsername: video.creator.username,
            creatorAvatarUrl: video.creator.avatarUrl,
        });
    }
    const video = store_1.db.videos.get(id);
    if (!video)
        return null;
    const creator = store_1.db.users.get(video.creatorId);
    return {
        ...video,
        creatorDisplayName: creator?.displayName,
        creatorUsername: creator?.username,
        creatorAvatarUrl: creator?.avatarUrl ?? null,
    };
}
async function deleteVideo(id) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        await prisma_1.prisma.video.delete({ where: { id } });
        return;
    }
    store_1.db.videos.delete(id);
}
async function toggleLike(userId, videoId) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const existing = await prisma_1.prisma.like.findUnique({
            where: { userId_videoId: { userId, videoId } },
        });
        if (existing) {
            await prisma_1.prisma.$transaction(async (tx) => {
                await tx.like.delete({ where: { userId_videoId: { userId, videoId } } });
                await tx.video.update({
                    where: { id: videoId },
                    data: { likeCount: { decrement: 1 } },
                });
            });
            return false;
        }
        await prisma_1.prisma.$transaction(async (tx) => {
            await tx.like.create({ data: { userId, videoId } });
            await tx.video.update({
                where: { id: videoId },
                data: { likeCount: { increment: 1 } },
            });
        });
        return true;
    }
    const key = `${userId}:${videoId}`;
    const liked = store_1.db.likes.has(key);
    const video = store_1.db.videos.get(videoId);
    if (!video)
        return false;
    if (liked) {
        store_1.db.likes.delete(key);
        store_1.db.videos.set(video.id, { ...video, likeCount: Math.max(0, video.likeCount - 1) });
        return false;
    }
    store_1.db.likes.add(key);
    store_1.db.videos.set(video.id, { ...video, likeCount: video.likeCount + 1 });
    return true;
}
async function listComments(videoId) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const comments = await prisma_1.prisma.comment.findMany({
            where: { videoId },
            include: {
                author: {
                    select: {
                        displayName: true,
                        username: true,
                    },
                },
            },
            orderBy: { createdAt: 'asc' },
        });
        return comments.map((comment) => toComment({
            ...comment,
            authorDisplayName: comment.author.displayName,
            authorUsername: comment.author.username,
        }));
    }
    return [...store_1.db.comments.values()]
        .filter((comment) => comment.videoId === videoId)
        .sort((a, b) => a.createdAt.localeCompare(b.createdAt))
        .map((comment) => {
        const author = store_1.db.users.get(comment.authorId);
        return {
            ...comment,
            authorDisplayName: author?.displayName,
            authorUsername: author?.username,
        };
    });
}
async function addComment(videoId, authorId, text) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const created = await prisma_1.prisma.$transaction(async (tx) => {
            const comment = await tx.comment.create({
                data: {
                    id: (0, uuid_1.v4)(),
                    videoId,
                    authorId,
                    text,
                },
            });
            await tx.video.update({
                where: { id: videoId },
                data: { commentCount: { increment: 1 } },
            });
            return comment;
        });
        const user = await prisma_1.prisma.user.findUnique({
            where: { id: authorId },
            select: {
                displayName: true,
                username: true,
            },
        });
        return toComment({
            ...created,
            authorDisplayName: user?.displayName,
            authorUsername: user?.username,
        });
    }
    const id = (0, uuid_1.v4)();
    const created = {
        id,
        videoId,
        authorId,
        text,
        createdAt: new Date().toISOString(),
    };
    store_1.db.comments.set(id, created);
    const video = store_1.db.videos.get(videoId);
    if (video) {
        store_1.db.videos.set(video.id, { ...video, commentCount: video.commentCount + 1 });
    }
    const author = store_1.db.users.get(authorId);
    return {
        ...created,
        authorDisplayName: author?.displayName,
        authorUsername: author?.username,
    };
}
async function listFeed(page, pageSize) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const total = await prisma_1.prisma.video.count();
        const start = (page - 1) * pageSize;
        const videos = await prisma_1.prisma.video.findMany({
            orderBy: { createdAt: 'desc' },
            skip: start,
            take: pageSize,
            include: {
                creator: {
                    select: {
                        displayName: true,
                        username: true,
                        avatarUrl: true,
                    },
                },
            },
        });
        return {
            items: videos.map((video) => toVideoMeta({
                ...video,
                creatorDisplayName: video.creator.displayName,
                creatorUsername: video.creator.username,
                creatorAvatarUrl: video.creator.avatarUrl,
            })),
            total,
            hasMore: start + pageSize < total,
        };
    }
    const all = [...store_1.db.videos.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    const total = all.length;
    const start = (page - 1) * pageSize;
    const items = all.slice(start, start + pageSize).map((video) => {
        const creator = store_1.db.users.get(video.creatorId);
        return {
            ...video,
            creatorDisplayName: creator?.displayName,
            creatorUsername: creator?.username,
            creatorAvatarUrl: creator?.avatarUrl ?? null,
        };
    });
    return {
        items,
        total,
        hasMore: start + pageSize < total,
    };
}
async function listVideosByCreator(creatorId) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const videos = await prisma_1.prisma.video.findMany({
            where: { creatorId },
            orderBy: { createdAt: 'desc' },
            include: {
                creator: {
                    select: {
                        displayName: true,
                        username: true,
                        avatarUrl: true,
                    },
                },
            },
        });
        return videos.map((video) => toVideoMeta({
            ...video,
            creatorDisplayName: video.creator.displayName,
            creatorUsername: video.creator.username,
            creatorAvatarUrl: video.creator.avatarUrl,
        }));
    }
    return [...store_1.db.videos.values()]
        .filter((video) => video.creatorId === creatorId)
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
        .map((video) => {
        const creator = store_1.db.users.get(video.creatorId);
        return {
            ...video,
            creatorDisplayName: creator?.displayName,
            creatorUsername: creator?.username,
            creatorAvatarUrl: creator?.avatarUrl ?? null,
        };
    });
}
async function listProtectedVideoCandidates() {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const rows = await prisma_1.prisma.video.findMany({
            where: {
                OR: [
                    { originBundleId: { not: null } },
                    { description: { contains: '[origin_protection]' } },
                    { description: { contains: '[origin_fingerprint]' } },
                ],
            },
            select: {
                id: true,
                creatorId: true,
                title: true,
                originBundleId: true,
                description: true,
            },
        });
        return rows;
    }
    return [...store_1.db.videos.values()]
        .filter((video) => {
        const description = video.description ?? '';
        return Boolean(video.originBundleId ||
            description.includes('[origin_protection]') ||
            description.includes('[origin_fingerprint]'));
    })
        .map((video) => ({
        id: video.id,
        creatorId: video.creatorId,
        title: video.title,
        originBundleId: video.originBundleId,
        description: video.description,
    }));
}
function collectKeywords(value) {
    return (value.toLowerCase().match(/[a-z0-9]{4,}/g) ?? [])
        .filter((word) => !['video', 'with', 'from', 'this', 'that', 'your', 'have', 'will', 'about'].includes(word));
}
async function getUserInteractionSignals(userId) {
    const likedVideoIds = [];
    const commentedVideoIds = [];
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const [likes, comments] = await Promise.all([
            prisma_1.prisma.like.findMany({ where: { userId }, select: { videoId: true }, take: 500 }),
            prisma_1.prisma.comment.findMany({ where: { authorId: userId }, select: { videoId: true }, take: 500 }),
        ]);
        likedVideoIds.push(...likes.map((row) => row.videoId));
        commentedVideoIds.push(...comments.map((row) => row.videoId));
    }
    else {
        for (const key of store_1.db.likes.values()) {
            const [uid, vid] = key.split(':');
            if (uid === userId && vid)
                likedVideoIds.push(vid);
        }
        for (const comment of store_1.db.comments.values()) {
            if (comment.authorId === userId)
                commentedVideoIds.push(comment.videoId);
        }
    }
    const interacted = new Set([...likedVideoIds, ...commentedVideoIds]);
    const creatorCount = new Map();
    const keywordCount = new Map();
    if (interacted.size > 0) {
        const feed = await listFeed(1, 5000);
        for (const item of feed.items) {
            if (!interacted.has(item.id))
                continue;
            creatorCount.set(item.creatorId, (creatorCount.get(item.creatorId) ?? 0) + 1);
            for (const keyword of collectKeywords(`${item.title} ${item.description ?? ''}`)) {
                keywordCount.set(keyword, (keywordCount.get(keyword) ?? 0) + 1);
            }
        }
    }
    const preferredCreators = [...creatorCount.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 30)
        .map(([creatorId]) => creatorId);
    const topicKeywords = [...keywordCount.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 40)
        .map(([keyword]) => keyword);
    return {
        likedVideoIds,
        commentedVideoIds,
        preferredCreators,
        topicKeywords,
    };
}
//# sourceMappingURL=videoRepository.js.map