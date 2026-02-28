"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const zod_1 = require("zod");
const config_1 = require("../config");
const adminStore_1 = require("../services/adminStore");
const userRepository_1 = require("../repositories/userRepository");
const router = (0, express_1.Router)();
const registerSchema = zod_1.z.object({
    username: zod_1.z.string().min(3).max(32),
    email: zod_1.z.string().email(),
    password: zod_1.z.string().min(8),
    displayName: zod_1.z.string().max(64).optional(),
    acceptTerms: zod_1.z.literal(true),
    subscribeToProtection: zod_1.z.boolean().optional(),
});
const loginSchema = zod_1.z.object({
    email: zod_1.z.string().email(),
    password: zod_1.z.string(),
});
// POST /api/auth/register
router.post('/register', async (req, res) => {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const { username, email, password, displayName, subscribeToProtection } = parsed.data;
    const conflict = await (0, userRepository_1.findUserConflict)(email, username);
    if (conflict === 'email') {
        res.status(409).json({ error: 'Email already registered' });
        return;
    }
    if (conflict === 'username') {
        res.status(409).json({ error: 'Username already taken' });
        return;
    }
    const passwordHash = await bcryptjs_1.default.hash(password, 10);
    const user = await (0, userRepository_1.createUser)({
        username,
        email,
        displayName: displayName ?? username,
        avatarUrl: null,
        bio: null,
        creatorKeyId: null,
        passwordHash,
    });
    const token = jsonwebtoken_1.default.sign({ sub: user.id }, config_1.config.jwt.secret, {
        expiresIn: config_1.config.jwt.expiresIn,
    });
    res.status(201).json({
        user: (0, userRepository_1.toPublicUser)(user),
        token,
        onboarding: {
            subscribeToProtection: Boolean(subscribeToProtection),
        },
    });
});
// POST /api/auth/login
router.post('/login', async (req, res) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
        res.status(400).json({ error: parsed.error.flatten() });
        return;
    }
    const { email, password } = parsed.data;
    const user = await (0, userRepository_1.findUserByEmail)(email);
    if (!user || !(await bcryptjs_1.default.compare(password, user.passwordHash))) {
        res.status(401).json({ error: 'Invalid credentials' });
        return;
    }
    if (adminStore_1.adminStore.isUserBanned(user.id)) {
        res.status(403).json({ error: 'Account is suspended' });
        return;
    }
    const token = jsonwebtoken_1.default.sign({ sub: user.id }, config_1.config.jwt.secret, {
        expiresIn: config_1.config.jwt.expiresIn,
    });
    res.json({ user: (0, userRepository_1.toPublicUser)(user), token });
});
exports.default = router;
//# sourceMappingURL=auth.js.map