"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.STUDIO_FEATURES = void 0;
exports.getFeatureDefinition = getFeatureDefinition;
exports.STUDIO_FEATURES = [
    { key: 'trim', label: 'Trim', phase: 'phase1', kind: 'basic', providers: ['local'], estimateSeconds: 20, billableCredits: 0 },
    { key: 'captions', label: 'Captions', phase: 'phase1', kind: 'basic', providers: ['local'], estimateSeconds: 25, billableCredits: 0 },
    { key: 'filters', label: 'Filters', phase: 'phase1', kind: 'basic', providers: ['local'], estimateSeconds: 15, billableCredits: 0 },
    { key: 'templates', label: 'Templates', phase: 'phase1', kind: 'basic', providers: ['local'], estimateSeconds: 18, billableCredits: 0 },
    { key: 'auto_edit', label: 'Auto editing', phase: 'phase2', kind: 'assist', providers: ['runway', 'openai'], estimateSeconds: 180, billableCredits: 8 },
    { key: 'auto_caption_whisper', label: 'Auto captioning (Whisper)', phase: 'phase2', kind: 'assist', providers: ['openai'], estimateSeconds: 120, billableCredits: 5 },
    { key: 'noise_remove', label: 'Noise removal', phase: 'phase2', kind: 'assist', providers: ['rnnoise', 'demucs'], estimateSeconds: 200, billableCredits: 6 },
    { key: 'smart_crop', label: 'Smart cropping', phase: 'phase2', kind: 'assist', providers: ['openai', 'runway'], estimateSeconds: 160, billableCredits: 6 },
    { key: 'thumbnail_generate', label: 'Thumbnail generation', phase: 'phase2', kind: 'assist', providers: ['openai', 'luma'], estimateSeconds: 90, billableCredits: 4 },
    { key: 'text_to_video', label: 'Text to video', phase: 'phase3', kind: 'generate', providers: ['runway', 'pika', 'luma'], estimateSeconds: 420, billableCredits: 20 },
    { key: 'describe_to_animate', label: 'Describe to animate', phase: 'phase3', kind: 'generate', providers: ['runway', 'pika'], estimateSeconds: 380, billableCredits: 18 },
    { key: 'ai_dialogue', label: 'AI dialogue', phase: 'phase3', kind: 'generate', providers: ['openai'], estimateSeconds: 210, billableCredits: 12 },
    { key: 'ai_voice_acting', label: 'AI voice acting', phase: 'phase3', kind: 'generate', providers: ['elevenlabs', 'openai'], estimateSeconds: 260, billableCredits: 14 },
    { key: 'lip_sync', label: 'Lip sync', phase: 'phase3', kind: 'generate', providers: ['runway', 'luma'], estimateSeconds: 340, billableCredits: 16 },
    { key: 'character_consistency', label: 'Character consistency', phase: 'phase3', kind: 'generate', providers: ['runway', 'pika', 'luma'], estimateSeconds: 500, billableCredits: 24 },
];
function getFeatureDefinition(key) {
    return exports.STUDIO_FEATURES.find((item) => item.key === key);
}
//# sourceMappingURL=featureCatalog.js.map