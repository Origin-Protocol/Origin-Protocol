"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.toPublicUser = toPublicUser;
exports.findUserById = findUserById;
exports.findUserByEmail = findUserByEmail;
exports.findUserByUsername = findUserByUsername;
exports.findUserConflict = findUserConflict;
exports.createUser = createUser;
exports.updateUser = updateUser;
exports.updateUserPassword = updateUserPassword;
exports.searchUsers = searchUsers;
const config_1 = require("../config");
const uuid_1 = require("uuid");
const prisma_1 = require("../models/prisma");
const store_1 = require("../models/store");
function toUserWithPassword(user) {
    return {
        id: user.id,
        username: user.username,
        email: user.email,
        displayName: user.displayName,
        avatarUrl: user.avatarUrl,
        bio: user.bio,
        creatorKeyId: user.creatorKeyId,
        createdAt: typeof user.createdAt === 'string'
            ? user.createdAt
            : user.createdAt.toISOString(),
        passwordHash: user.passwordHash,
    };
}
function toPublicUser(user) {
    const { passwordHash: _passwordHash, ...publicUser } = user;
    return publicUser;
}
async function findUserById(id) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const user = await prisma_1.prisma.user.findUnique({ where: { id } });
        return user ? toUserWithPassword(user) : null;
    }
    return store_1.db.users.get(id) ?? null;
}
async function findUserByEmail(email) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const user = await prisma_1.prisma.user.findUnique({ where: { email } });
        return user ? toUserWithPassword(user) : null;
    }
    return [...store_1.db.users.values()].find((user) => user.email === email) ?? null;
}
async function findUserByUsername(username) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const user = await prisma_1.prisma.user.findUnique({ where: { username } });
        return user ? toUserWithPassword(user) : null;
    }
    return [...store_1.db.users.values()].find((user) => user.username === username) ?? null;
}
async function findUserConflict(email, username) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const conflict = await prisma_1.prisma.user.findFirst({
            where: {
                OR: [{ email }, { username }],
            },
        });
        if (!conflict)
            return null;
        return conflict.email === email ? 'email' : 'username';
    }
    for (const user of store_1.db.users.values()) {
        if (user.email === email)
            return 'email';
        if (user.username === username)
            return 'username';
    }
    return null;
}
async function createUser(input) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const created = await prisma_1.prisma.user.create({
            data: {
                username: input.username,
                email: input.email,
                displayName: input.displayName,
                avatarUrl: input.avatarUrl ?? null,
                bio: input.bio ?? null,
                creatorKeyId: input.creatorKeyId ?? null,
                passwordHash: input.passwordHash,
            },
        });
        return toUserWithPassword(created);
    }
    const id = (0, uuid_1.v4)();
    const created = {
        id,
        username: input.username,
        email: input.email,
        displayName: input.displayName,
        avatarUrl: input.avatarUrl ?? null,
        bio: input.bio ?? null,
        creatorKeyId: input.creatorKeyId ?? null,
        createdAt: new Date().toISOString(),
        passwordHash: input.passwordHash,
    };
    store_1.db.users.set(created.id, created);
    return created;
}
async function updateUser(userId, updates) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const existing = await prisma_1.prisma.user.findUnique({ where: { id: userId } });
        if (!existing)
            return null;
        const updated = await prisma_1.prisma.user.update({
            where: { id: userId },
            data: updates,
        });
        return toUserWithPassword(updated);
    }
    const existing = store_1.db.users.get(userId);
    if (!existing)
        return null;
    const updated = {
        ...existing,
        ...updates,
    };
    store_1.db.users.set(updated.id, updated);
    return updated;
}
async function updateUserPassword(userId, passwordHash) {
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const existing = await prisma_1.prisma.user.findUnique({ where: { id: userId } });
        if (!existing)
            return null;
        const updated = await prisma_1.prisma.user.update({
            where: { id: userId },
            data: { passwordHash },
        });
        return toUserWithPassword(updated);
    }
    const existing = store_1.db.users.get(userId);
    if (!existing)
        return null;
    const updated = {
        ...existing,
        passwordHash,
    };
    store_1.db.users.set(updated.id, updated);
    return updated;
}
async function searchUsers(query, limit = 12) {
    const term = query.trim().toLowerCase();
    if (!term)
        return [];
    const safeLimit = Math.max(1, Math.min(limit, 30));
    if (config_1.config.database.usePrisma && prisma_1.prisma) {
        const users = await prisma_1.prisma.user.findMany({
            where: {
                OR: [
                    { id: { contains: term } },
                    { username: { contains: term, mode: 'insensitive' } },
                    { displayName: { contains: term, mode: 'insensitive' } },
                ],
            },
            orderBy: { createdAt: 'desc' },
            take: safeLimit,
        });
        return users.map(toUserWithPassword);
    }
    return [...store_1.db.users.values()]
        .filter((user) => {
        const id = user.id.toLowerCase();
        const username = user.username.toLowerCase();
        const displayName = user.displayName.toLowerCase();
        return id.includes(term) || username.includes(term) || displayName.includes(term);
    })
        .slice(0, safeLimit);
}
//# sourceMappingURL=userRepository.js.map