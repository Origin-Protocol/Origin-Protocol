export type PersonalInformationSettings = {
    displayName: string;
    username: string;
    bio: string;
    profilePhoto: string;
    bannerPhoto: string;
    pronouns: string;
    birthday: string;
    location: string;
    contactEmail: string;
    phoneNumber: string;
};
export type PrivacySafetySettings = {
    whoCanMessageMe: 'everyone' | 'friends' | 'followers' | 'no_one';
    whoCanSeeMyPosts: 'public' | 'followers' | 'private';
    blockedUsers: string[];
    mutedUsers: string[];
    twoFactorAuthEnabled: boolean;
    loginAlertsEnabled: boolean;
    pauseAbigailMemoryCollection: boolean;
};
export type PreferencesSettings = {
    notificationMode: 'all' | 'important' | 'minimal';
    feedTuning: 'balanced' | 'following_first' | 'discovery_first';
    contentPreferences: string[];
    theme: 'dark' | 'light' | 'system';
    language: string;
    sensitiveContent: 'strict' | 'moderate' | 'permissive';
    abigailTone: 'professional' | 'casual' | 'concise' | 'detailed';
};
export type BillingPurchasesSettings = {
    subscriptions: Array<{
        id: string;
        name: string;
        status: 'active' | 'paused' | 'canceled';
        renewalAt?: string;
    }>;
    paymentMethods: Array<{
        id: string;
        brand: string;
        last4: string;
        expMonth: number;
        expYear: number;
    }>;
    billingHistory: Array<{
        id: string;
        amountUsd: number;
        createdAt: string;
        description: string;
    }>;
    receipts: Array<{
        id: string;
        title: string;
        url: string;
        createdAt: string;
    }>;
    autoRenewEnabled: boolean;
};
export type SessionItem = {
    id: string;
    deviceName: string;
    location: string;
    ipAddress: string;
    lastSeenAt: string;
    current: boolean;
};
export type DevicesSessionsSettings = {
    activeSessions: SessionItem[];
    deviceList: SessionItem[];
    loginHistory: Array<{
        id: string;
        deviceName: string;
        location: string;
        ipAddress: string;
        createdAt: string;
    }>;
};
export type AbigailPersonalizationSettings = {
    userGoals: string[];
    habits: string[];
    interests: string[];
    learningStyle: string;
    memorySummary: string;
};
export type AccountManagementSettings = {
    legalAgreementsAcceptedAt: string;
    ageVerificationStatus: 'unverified' | 'pending' | 'verified';
};
export type UserSettings = {
    userId: string;
    personalInformation: PersonalInformationSettings;
    privacySafety: PrivacySafetySettings;
    preferences: PreferencesSettings;
    billingPurchases: BillingPurchasesSettings;
    devicesSessions: DevicesSessionsSettings;
    abigailPersonalization: AbigailPersonalizationSettings;
    accountManagement: AccountManagementSettings;
    updatedAt: string;
};
declare class UserSettingsStore {
    private readonly items;
    constructor();
    private flush;
    ensure(user: {
        id: string;
        displayName: string;
        username: string;
        email: string;
        bio?: string | null;
        avatarUrl?: string | null;
    }): UserSettings;
    get(user: {
        id: string;
        displayName: string;
        username: string;
        email: string;
        bio?: string | null;
        avatarUrl?: string | null;
    }): UserSettings;
    update(user: {
        id: string;
        displayName: string;
        username: string;
        email: string;
        bio?: string | null;
        avatarUrl?: string | null;
    }, patch: Partial<UserSettings>): UserSettings;
    revokeSession(user: {
        id: string;
        displayName: string;
        username: string;
        email: string;
        bio?: string | null;
        avatarUrl?: string | null;
    }, sessionId: string): UserSettings;
    export(user: {
        id: string;
        displayName: string;
        username: string;
        email: string;
        bio?: string | null;
        avatarUrl?: string | null;
    }): {
        settings: UserSettings;
        exportedAt: string;
    };
    delete(userId: string): void;
}
export declare const userSettingsStore: UserSettingsStore;
export {};
//# sourceMappingURL=userSettingsStore.d.ts.map