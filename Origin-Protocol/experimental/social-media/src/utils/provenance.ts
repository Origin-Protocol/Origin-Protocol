import type { VideoMeta } from '../types';

type ProtectionMeta = {
  protected?: boolean;
  revealMode?: string;
  options?: string[];
  platforms?: string[];
  [key: string]: unknown;
};

export function parseProtectionMeta(description: string | null | undefined): {
  cleanDescription: string;
  protectionMeta: ProtectionMeta | null;
} {
  const text = (description ?? '').trim();
  if (!text) {
    return { cleanDescription: '', protectionMeta: null };
  }

  const metadataMatch = text.match(/\[\[ORIGIN:([\s\S]*?)\]\]\s*$/i);
  if (!metadataMatch) {
    return { cleanDescription: text, protectionMeta: null };
  }

  const rawMeta = metadataMatch[1]?.trim();
  const cleanDescription = text.replace(metadataMatch[0], '').trim();
  if (!rawMeta) {
    return { cleanDescription, protectionMeta: null };
  }

  try {
    const parsed = JSON.parse(rawMeta);
    if (parsed && typeof parsed === 'object') {
      return { cleanDescription, protectionMeta: parsed as ProtectionMeta };
    }
  } catch {
    return { cleanDescription: text, protectionMeta: null };
  }

  return { cleanDescription, protectionMeta: null };
}

export function buildProvenanceReport(video: VideoMeta, source: string): Record<string, unknown> {
  const { cleanDescription, protectionMeta } = parseProtectionMeta(video.description);

  return {
    generatedAt: new Date().toISOString(),
    source,
    video: {
      id: video.id,
      title: video.title,
      description: cleanDescription,
      creatorId: video.creatorId,
      creatorDisplayName: video.creatorDisplayName ?? null,
      creatorUsername: video.creatorUsername ?? null,
      createdAt: video.createdAt,
      media: {
        videoUrl: video.videoUrl,
        thumbnailUrl: video.thumbnailUrl,
        duration: video.duration,
      },
      stats: {
        likes: video.likeCount,
        comments: video.commentCount,
        views: video.viewCount,
      },
      origin: {
        bundleId: video.originBundleId,
        verified: video.originVerified,
        reasons: video.originReasons ?? [],
        checkedAt: video.originVerificationCheckedAt ?? null,
        protectionMeta,
      },
    },
  };
}
