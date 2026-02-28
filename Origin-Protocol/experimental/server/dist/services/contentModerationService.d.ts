type ModerationInput = {
    creatorId: string;
    title?: string;
    description?: string;
    videoUrl?: string;
    streamUid?: string;
    source: 'sealed' | 'cloudflare-finalize' | 'direct-upload';
};
type ModerationDecision = {
    allowed: boolean;
    provider: 'local-keywords' | 'cloudflare-worker' | 'cloudflare-ai' | 'none';
    reason?: string;
    matchedTerms?: string[];
    categories?: string[];
};
export declare const contentModerationService: {
    evaluate(input: ModerationInput): Promise<ModerationDecision>;
};
export {};
//# sourceMappingURL=contentModerationService.d.ts.map