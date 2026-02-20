import { VideoMeta } from '../types';
import { videosApi } from '../api/client';
import { useState } from 'react';

interface Props {
  video: VideoMeta;
}

export default function VideoCard({ video }: Props) {
  const [liked, setLiked] = useState(false);
  const [likeCount, setLikeCount] = useState(video.likeCount);

  async function handleLike() {
    try {
      const res = await videosApi.like(video.id);
      setLiked(res.liked);
      setLikeCount((c) => res.liked ? c + 1 : Math.max(0, c - 1));
    } catch {
      // ignore — user may not be logged in
    }
  }

  return (
    <article style={{ borderBottom: '1px solid #eee', paddingBottom: 16, marginBottom: 16 }}>
      <video
        src={video.videoUrl}
        controls
        style={{ width: '100%', background: '#000', maxHeight: 480 }}
        poster={video.thumbnailUrl ?? undefined}
      />
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <strong>{video.title}</strong>
          {video.description && <p style={{ margin: '4px 0', color: '#444', fontSize: 14 }}>{video.description}</p>}
          {video.originVerified && (
            <span style={{ fontSize: 12, color: 'green' }}>✅ Origin-verified</span>
          )}
        </div>
        <button onClick={() => void handleLike()} style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 20 }}>
          {liked ? '❤️' : '🤍'} {likeCount}
        </button>
      </div>
      <p style={{ margin: '4px 0', fontSize: 12, color: '#888' }}>
        👁 {video.viewCount}  💬 {video.commentCount}  •  {new Date(video.createdAt).toLocaleDateString()}
      </p>
    </article>
  );
}
