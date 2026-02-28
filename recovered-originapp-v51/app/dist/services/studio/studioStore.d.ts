import { StudioCredits, StudioJob } from '../../types/studio';
type StudioUsageCounter = {
    generate: number;
    edit: number;
};
export declare const studioStore: {
    getJobs(): StudioJob[];
    setJobs(jobs: StudioJob[]): void;
    getQueue(): string[];
    setQueue(queue: string[]): void;
    getCreditsRecord(): Record<string, StudioCredits>;
    setCreditsRecord(record: Record<string, StudioCredits>): void;
    getUsageRecord(): Record<string, StudioUsageCounter>;
    setUsageRecord(record: Record<string, StudioUsageCounter>): void;
};
export {};
//# sourceMappingURL=studioStore.d.ts.map