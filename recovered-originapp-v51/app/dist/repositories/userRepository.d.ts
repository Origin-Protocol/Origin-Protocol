import { UpdateProfileBody, User } from '../types';
export type UserWithPassword = User & {
    passwordHash: string;
};
type CreateUserInput = {
    username: string;
    email: string;
    displayName: string;
    passwordHash: string;
    avatarUrl?: string | null;
    bio?: string | null;
    creatorKeyId?: string | null;
};
export declare function toPublicUser(user: UserWithPassword): User;
export declare function findUserById(id: string): Promise<UserWithPassword | null>;
export declare function findUserByEmail(email: string): Promise<UserWithPassword | null>;
export declare function findUserByUsername(username: string): Promise<UserWithPassword | null>;
export declare function findUserConflict(email: string, username: string): Promise<'email' | 'username' | null>;
export declare function createUser(input: CreateUserInput): Promise<UserWithPassword>;
export declare function updateUser(userId: string, updates: UpdateProfileBody): Promise<UserWithPassword | null>;
export declare function updateUserPassword(userId: string, passwordHash: string): Promise<UserWithPassword | null>;
export declare function searchUsers(query: string, limit?: number): Promise<UserWithPassword[]>;
export {};
//# sourceMappingURL=userRepository.d.ts.map