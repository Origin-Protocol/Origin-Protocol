export type SyncHistoryItem = {
  id: string;
  source: string;
  status: 'pending' | 'success' | 'failed';
  createdAt: string;
  title?: string;
  videoId?: string;
  payloadJson?: string;
  message?: string;
};
