import { StudioCredits } from '../../types/studio';
export declare const studioCreditsService: {
    get(userId: string): StudioCredits;
    setTier(userId: string, tier: "free" | "paid"): StudioCredits;
    canReserve(userId: string, amount: number): boolean;
    reserve(userId: string, amount: number): void;
    settle(userId: string, amount: number, succeeded: boolean): void;
    addCredits(userId: string, amount: number): StudioCredits;
};
//# sourceMappingURL=creditsService.d.ts.map