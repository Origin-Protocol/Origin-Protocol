"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = require("express");
const stripe_1 = __importDefault(require("stripe"));
const auth_1 = require("../middleware/auth");
const config_1 = require("../config");
const userRepository_1 = require("../repositories/userRepository");
const adminStore_1 = require("../services/adminStore");
const creditsService_1 = require("../services/studio/creditsService");
const router = (0, express_1.Router)();
const stripe = config_1.config.membership.stripeSecretKey ? new stripe_1.default(config_1.config.membership.stripeSecretKey) : null;
const CREATOR_PLAN_CATALOG = [
    {
        id: 'ai-video-suite-monthly',
        name: 'AI Video Suite — Monthly',
        description: '$19/month creator access for premium AI video generation.',
        productId: 'prod_U2RmK26Xfl3yAo',
        mode: 'subscription',
        billingType: 'creator',
    },
    {
        id: 'ai-video-suite-yearly',
        name: 'AI Video Suite — Yearly',
        description: '$180/year creator access.',
        productId: 'prod_U2RnhQh9UQht65',
        mode: 'subscription',
        billingType: 'creator',
    },
    {
        id: 'credits-50',
        name: 'Credit Pack — 50 Credits',
        description: '$5 one-time credit pack.',
        productId: 'prod_U2RpZDiyPwSihM',
        mode: 'payment',
        billingType: 'creator',
    },
    {
        id: 'credits-120',
        name: 'Credit Pack — 120 Credits',
        description: '$10 one-time credit pack.',
        productId: 'prod_U2RqkpdsHa0KK2',
        mode: 'payment',
        billingType: 'creator',
    },
    {
        id: 'credits-300',
        name: 'Credit Pack — 300 Credits',
        description: '$20 one-time credit pack.',
        productId: 'prod_U2RqwLIYKk1Qcf',
        mode: 'payment',
        billingType: 'creator',
    },
];
const PLATFORM_PLAN_CATALOG = {
    id: 'platform-metered',
    name: 'Platform Integration — Metered Usage',
    description: 'Usage-based billing once your platform integrates with Origin Protocol.',
    productId: 'prod_U1hxB4m2bjbrs6',
    mode: 'subscription',
    billingType: 'platform',
};
const CREATOR_ACCESS_PRODUCT_IDS = new Set([
    'prod_U2RmK26Xfl3yAo',
    'prod_U2RnhQh9UQht65',
]);
const CREDIT_PACK_BY_PRODUCT_ID = new Map([
    ['prod_U2RpZDiyPwSihM', 50],
    ['prod_U2RqkpdsHa0KK2', 120],
    ['prod_U2RqwLIYKk1Qcf', 300],
]);
function buildCreatorKeyId(userId) {
    return `origin-key-${userId.slice(0, 8)}-${Date.now().toString(36)}`;
}
function isAdminBypassEmail(email) {
    const normalized = email.trim().toLowerCase();
    return config_1.config.membership.adminEmails.includes(normalized);
}
function isAdminUser(user) {
    return isAdminBypassEmail(user.email) || adminStore_1.adminStore.isPromotedAdmin(user.id);
}
async function ensureCreatorMembership(userId) {
    const current = await (0, userRepository_1.findUserById)(userId);
    if (!current)
        return null;
    if (current.creatorKeyId)
        return current;
    const updated = await (0, userRepository_1.updateUser)(current.id, {
        creatorKeyId: buildCreatorKeyId(current.id),
    });
    return updated;
}
function isStripeSubscriptionActive(status) {
    return status === 'active' || status === 'trialing' || status === 'past_due' || status === 'unpaid';
}
async function findStripeCustomerByEmail(email) {
    if (!stripe)
        return null;
    const customers = await stripe.customers.list({ email, limit: 1 });
    const customer = customers.data[0];
    return customer ?? null;
}
async function hasActiveStripeMembership(email) {
    if (!stripe)
        return false;
    const customer = await findStripeCustomerByEmail(email);
    if (!customer)
        return false;
    const subscriptions = await stripe.subscriptions.list({
        customer: customer.id,
        status: 'all',
        limit: 25,
    });
    return subscriptions.data.some((subscription) => isStripeSubscriptionActive(subscription.status));
}
function normalizeCheckoutMode(value) {
    return value === 'payment' ? 'payment' : 'subscription';
}
function pickPriceByMode(prices, mode) {
    if (mode === 'payment') {
        const oneTime = prices.data.find((price) => price.type === 'one_time');
        return oneTime?.id ?? null;
    }
    const recurring = prices.data.find((price) => price.type === 'recurring' && Boolean(price.recurring));
    return recurring?.id ?? null;
}
async function resolveStripePriceId(options) {
    if (!stripe)
        return { priceId: null, mode: normalizeCheckoutMode(options.mode) };
    const mode = normalizeCheckoutMode(options.mode);
    const lookupKey = (options.lookupKey ?? '').trim();
    const productId = (options.productId ?? '').trim();
    if (lookupKey) {
        const prices = await stripe.prices.list({
            lookup_keys: [lookupKey],
            expand: ['data.product'],
            limit: 1,
        });
        return { priceId: prices.data[0]?.id ?? null, mode };
    }
    if (productId) {
        const prices = await stripe.prices.list({
            product: productId,
            active: true,
            expand: ['data.product'],
            limit: 100,
        });
        return { priceId: pickPriceByMode(prices, mode), mode };
    }
    if (config_1.config.membership.stripePriceId)
        return { priceId: config_1.config.membership.stripePriceId, mode };
    if (config_1.config.membership.stripePriceLookupKey.trim()) {
        const fallbackByLookup = await stripe.prices.list({
            lookup_keys: [config_1.config.membership.stripePriceLookupKey.trim()],
            expand: ['data.product'],
            limit: 1,
        });
        return { priceId: fallbackByLookup.data[0]?.id ?? null, mode };
    }
    const fallbackProduct = config_1.config.membership.stripeDefaultCreatorProductId.trim();
    if (!fallbackProduct)
        return { priceId: null, mode };
    const prices = await stripe.prices.list({
        product: fallbackProduct,
        active: true,
        expand: ['data.product'],
        limit: 100,
    });
    return { priceId: pickPriceByMode(prices, mode), mode };
}
router.get('/catalog', (_req, res) => {
    res.json({
        checkoutEnabled: Boolean(stripe),
        creatorPlans: CREATOR_PLAN_CATALOG,
        platformPlan: PLATFORM_PLAN_CATALOG,
        defaults: {
            creatorProductId: config_1.config.membership.stripeDefaultCreatorProductId,
            mode: 'subscription',
        },
    });
});
router.get('/payment-link', (_req, res) => {
    res.status(410).json({
        error: 'Temporary payment links are removed. Use Stripe checkout via /api/membership/create-checkout-session.',
    });
});
router.get('/status', auth_1.requireAuth, async (req, res) => {
    const existing = await (0, userRepository_1.findUserById)(req.userId);
    if (!existing) {
        res.status(404).json({ error: 'User not found' });
        return;
    }
    const isAdmin = isAdminUser(existing);
    let user = isAdmin ? await ensureCreatorMembership(existing.id) : existing;
    if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
    }
    const stripeActive = !isAdmin && stripe ? await hasActiveStripeMembership(user.email) : false;
    if (!isAdmin && stripeActive && !user.creatorKeyId) {
        user = await ensureCreatorMembership(user.id);
        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }
    }
    const active = Boolean(user.creatorKeyId) && (isAdmin || stripeActive || !stripe);
    res.json({
        active,
        creatorKeyId: user.creatorKeyId,
        billingProvider: 'stripe',
        checkoutEnabled: Boolean(stripe),
        publishableKey: config_1.config.membership.stripePublishableKey,
        meterId: config_1.config.membership.stripeMeterId || null,
        meterEventName: config_1.config.membership.stripeMeterEventName,
        isAdmin,
        user: (0, userRepository_1.toPublicUser)(user),
    });
});
router.post('/activate-temp', auth_1.requireAuth, async (_req, res) => {
    res.status(410).json({
        error: 'Temporary activation is removed. Complete Stripe checkout instead.',
    });
});
router.post('/create-checkout-session', auth_1.requireAuth, async (req, res) => {
    if (!stripe) {
        res.status(503).json({ error: 'Stripe billing is not configured on this server.' });
        return;
    }
    const existing = await (0, userRepository_1.findUserById)(req.userId);
    if (!existing) {
        res.status(404).json({ error: 'User not found' });
        return;
    }
    if (isAdminUser(existing)) {
        const user = await ensureCreatorMembership(existing.id);
        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }
        res.json({
            active: true,
            creatorKeyId: user.creatorKeyId,
            isAdmin: true,
            user: (0, userRepository_1.toPublicUser)(user),
            checkoutBypassed: true,
        });
        return;
    }
    const alreadyActive = await hasActiveStripeMembership(existing.email);
    if (alreadyActive) {
        const user = await ensureCreatorMembership(existing.id);
        if (!user) {
            res.status(404).json({ error: 'User not found' });
            return;
        }
        res.json({
            active: true,
            creatorKeyId: user.creatorKeyId,
            isAdmin: false,
            user: (0, userRepository_1.toPublicUser)(user),
            checkoutBypassed: true,
        });
        return;
    }
    const body = req.body;
    const selectedMode = normalizeCheckoutMode(body?.mode);
    const resolved = await resolveStripePriceId({
        lookupKey: body?.lookupKey,
        productId: body?.productId,
        mode: selectedMode,
    });
    const priceId = resolved?.priceId ?? null;
    if (!priceId) {
        res.status(500).json({ error: 'Stripe price configuration is missing.' });
        return;
    }
    const session = await stripe.checkout.sessions.create({
        mode: resolved.mode,
        payment_method_types: ['card'],
        customer_email: existing.email,
        line_items: [{ price: priceId, quantity: 1 }],
        success_url: config_1.config.membership.stripeSuccessUrl,
        cancel_url: config_1.config.membership.stripeCancelUrl,
        metadata: {
            userId: existing.id,
            email: existing.email,
            billingType: body?.billingType ?? 'creator',
            checkoutMode: resolved.mode,
            productId: body?.productId ?? '',
        },
        allow_promotion_codes: true,
    });
    if (!session.url) {
        res.status(500).json({ error: 'Stripe did not return a checkout URL.' });
        return;
    }
    adminStore_1.adminStore.appendUsageEvent({
        metric: 'stripe_checkout_started',
        value: 1,
        userId: existing.id,
        source: 'billing',
    });
    res.json({ url: session.url, sessionId: session.id });
});
router.post('/create-portal-session', auth_1.requireAuth, async (req, res) => {
    if (!stripe) {
        res.status(503).json({ error: 'Stripe billing is not configured on this server.' });
        return;
    }
    const existing = await (0, userRepository_1.findUserById)(req.userId);
    if (!existing) {
        res.status(404).json({ error: 'User not found' });
        return;
    }
    const customer = await findStripeCustomerByEmail(existing.email);
    if (!customer) {
        res.status(400).json({ error: 'No Stripe customer found for this account yet.' });
        return;
    }
    const returnUrl = `${config_1.config.membership.frontendBaseUrl}/upload`;
    const portalSession = await stripe.billingPortal.sessions.create({
        customer: customer.id,
        return_url: returnUrl,
    });
    res.json({ url: portalSession.url });
});
router.post('/meter-event', auth_1.requireAuth, async (req, res) => {
    if (!stripe) {
        res.status(503).json({ error: 'Stripe billing is not configured on this server.' });
        return;
    }
    const existing = await (0, userRepository_1.findUserById)(req.userId);
    if (!existing) {
        res.status(404).json({ error: 'User not found' });
        return;
    }
    const customer = await findStripeCustomerByEmail(existing.email);
    if (!customer) {
        res.status(400).json({ error: 'No Stripe customer found for this account.' });
        return;
    }
    const body = req.body;
    const eventName = (body?.eventName ?? config_1.config.membership.stripeMeterEventName).trim();
    const value = Number.isFinite(body?.value) ? Number(body.value) : 1;
    const timestamp = Number.isFinite(body?.timestamp)
        ? Math.floor(Number(body.timestamp))
        : Math.floor(Date.now() / 1000);
    if (!eventName) {
        res.status(400).json({ error: 'Meter event name is required.' });
        return;
    }
    if (value <= 0) {
        res.status(400).json({ error: 'Meter event value must be greater than 0.' });
        return;
    }
    await stripe.billing.meterEvents.create({
        event_name: eventName,
        timestamp,
        payload: {
            stripe_customer_id: customer.id,
            value: String(value),
        },
    });
    adminStore_1.adminStore.appendUsageEvent({
        metric: eventName,
        value,
        userId: existing.id,
        source: 'stripe-meter',
    });
    res.json({ ok: true, eventName, value, timestamp });
});
router.post('/webhook', async (req, res) => {
    if (!stripe) {
        res.status(503).json({ error: 'Stripe billing is not configured on this server.' });
        return;
    }
    const signature = req.headers['stripe-signature'];
    const webhookSecret = config_1.config.membership.stripeWebhookSecret;
    if (typeof signature !== 'string' || !webhookSecret) {
        res.status(400).json({ error: 'Missing Stripe webhook signature or secret.' });
        return;
    }
    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, signature, webhookSecret);
    }
    catch (error) {
        const message = error instanceof Error ? error.message : 'Invalid webhook signature';
        adminStore_1.adminStore.appendErrorLog({
            source: 'stripe-webhook',
            message,
            level: 'error',
        });
        res.status(400).json({ error: message });
        return;
    }
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const metadataUserId = session.metadata?.userId;
        const metadataProductId = (session.metadata?.productId ?? '').trim();
        const customerEmail = session.customer_details?.email ?? session.customer_email ?? undefined;
        let targetUser = metadataUserId ? await (0, userRepository_1.findUserById)(metadataUserId) : null;
        if (!targetUser && customerEmail) {
            targetUser = await (0, userRepository_1.findUserByEmail)(customerEmail);
        }
        if (targetUser && CREATOR_ACCESS_PRODUCT_IDS.has(metadataProductId) && !targetUser.creatorKeyId) {
            await (0, userRepository_1.updateUser)(targetUser.id, { creatorKeyId: buildCreatorKeyId(targetUser.id) });
        }
        if (targetUser) {
            const creditPackAmount = CREDIT_PACK_BY_PRODUCT_ID.get(metadataProductId) ?? 0;
            if (creditPackAmount > 0) {
                creditsService_1.studioCreditsService.addCredits(targetUser.id, creditPackAmount);
                adminStore_1.adminStore.appendUsageEvent({
                    metric: 'studio_credit_pack_granted',
                    value: creditPackAmount,
                    userId: targetUser.id,
                    source: 'stripe-webhook',
                });
            }
        }
        adminStore_1.adminStore.appendUsageEvent({
            metric: 'stripe_checkout_completed',
            value: 1,
            userId: targetUser?.id,
            source: 'stripe-webhook',
        });
    }
    if (event.type === 'invoice.payment_succeeded') {
        const invoice = event.data.object;
        const customerEmail = invoice.customer_email ?? undefined;
        if (!customerEmail) {
            res.json({ received: true });
            return;
        }
        const targetUser = await (0, userRepository_1.findUserByEmail)(customerEmail);
        if (targetUser && !targetUser.creatorKeyId) {
            await (0, userRepository_1.updateUser)(targetUser.id, { creatorKeyId: buildCreatorKeyId(targetUser.id) });
        }
        adminStore_1.adminStore.appendUsageEvent({
            metric: 'stripe_invoice_paid',
            value: 1,
            userId: targetUser?.id,
            source: 'stripe-webhook',
        });
    }
    res.json({ received: true });
});
exports.default = router;
//# sourceMappingURL=membership.js.map