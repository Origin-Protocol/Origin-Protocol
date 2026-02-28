/**
 * In-memory store used during development.
 *
 * Durable local persistence store used during development.
 *
 * Persists to `.data/store.json` inside the server workspace.
 * The public interface remains Map/Set-compatible so route code
 * does not need changes.
 */
import { User, VideoMeta, Comment } from '../types';
declare class PersistedMap<K, V> extends Map<K, V> {
    private readonly onMutate;
    constructor(entries: readonly (readonly [K, V])[] | null | undefined, onMutate: () => void);
    set(key: K, value: V): this;
    delete(key: K): boolean;
    clear(): void;
}
declare class PersistedSet<T> extends Set<T> {
    private readonly onMutate;
    constructor(values: readonly T[] | null | undefined, onMutate: () => void);
    add(value: T): this;
    delete(value: T): boolean;
    clear(): void;
}
export declare const db: {
    users: PersistedMap<string, User & {
        passwordHash: string;
    }>;
    videos: PersistedMap<string, VideoMeta>;
    comments: PersistedMap<string, Comment>;
    likes: PersistedSet<string>;
};
export {};
//# sourceMappingURL=store.d.ts.map