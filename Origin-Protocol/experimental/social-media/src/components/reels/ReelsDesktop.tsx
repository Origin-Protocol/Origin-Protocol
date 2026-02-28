import { useEffect } from 'react';
import type { VideoMeta } from '../../types';
import VideoCard from '../VideoCard';

type Props = {
  videos: VideoMeta[];
  onRequestMore?: () => void;
};

export default function ReelsDesktop({ videos, onRequestMore }: Props) {
  useEffect(() => {
    if (videos.length < 6) {
      onRequestMore?.();
    }
  }, [videos.length, onRequestMore]);

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      {videos.map((video) => (
        <VideoCard key={video.id} video={video} />
      ))}
    </div>
  );
}
