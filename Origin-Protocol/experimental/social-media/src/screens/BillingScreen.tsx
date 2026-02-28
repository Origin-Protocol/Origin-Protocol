import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { membershipApi } from '../api/client';
import { BILLING_PLANS } from '../config/pricing';

type MembershipStatus = {
  active: boolean;
  checkoutEnabled: boolean;
};

export default function BillingScreen() {
  const [status, setStatus] = useState<MembershipStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyPlanId, setBusyPlanId] = useState<string | null>(null);
  const [portalBusy, setPortalBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      try {
        const res = await membershipApi.status();
        if (!cancelled) {
          setStatus({ active: Boolean(res.active), checkoutEnabled: Boolean(res.checkoutEnabled) });
        }
      } catch (err) {
        if (!cancelled) {
          setError((err as Error).message || 'Failed to load billing status.');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  const checkoutDisabled = !status?.checkoutEnabled;

  const grouped = useMemo(() => {
    const credits = BILLING_PLANS.filter((item) => item.id.startsWith('origin-credits'));
    const subscriptions = BILLING_PLANS.filter((item) => !item.id.startsWith('origin-credits'));
    return { credits, subscriptions };
  }, []);

  async function startCheckout(planId: string) {
    const plan = BILLING_PLANS.find((item) => item.id === planId);
    if (!plan) return;
    if (!plan.productId.trim()) {
      setError(`Missing Stripe product ID for "${plan.name}".`);
      return;
    }

    setBusyPlanId(plan.id);
    setError(null);
    setMessage(null);
    try {
      const session = await membershipApi.createCheckoutSession({
        productId: plan.productId,
        mode: plan.mode,
        billingType: plan.billingType,
      });

      if (session.checkoutBypassed) {
        setMessage('Checkout bypassed for this account. Plan access is active.');
        return;
      }

      if (!session.url) {
        setError('Unable to create checkout session for this plan.');
        return;
      }

      window.location.href = session.url;
    } catch (err) {
      setError((err as Error).message || 'Unable to start Stripe checkout right now.');
    } finally {
      setBusyPlanId(null);
    }
  }

  async function openPortal() {
    setPortalBusy(true);
    setError(null);
    setMessage(null);
    try {
      const session = await membershipApi.createPortalSession();
      if (!session.url) {
        setError('Unable to open billing portal right now.');
        return;
      }
      window.open(session.url, '_blank', 'noopener,noreferrer');
    } catch (err) {
      setError((err as Error).message || 'Unable to open billing portal right now.');
    } finally {
      setPortalBusy(false);
    }
  }

  return (
    <main style={{ maxWidth: 1080, margin: '0 auto', color: '#e5e7eb', padding: 12, display: 'grid', gap: 12 }}>
      <section style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#0b1220', padding: 12 }}>
        <h1 style={{ margin: '0 0 8px' }}>Billing</h1>
        <p style={{ margin: 0, color: '#94a3b8' }}>
          Select a plan, launch Stripe checkout, or manage existing billing.
        </p>
        <div style={{ marginTop: 10, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button
            type="button"
            onClick={() => void openPortal()}
            disabled={portalBusy}
            style={{ borderRadius: 8, border: '1px solid #374151', background: '#111827', color: '#fff', padding: '8px 10px' }}
          >
            {portalBusy ? 'Opening portal…' : 'Manage billing'}
          </button>
          <Link to="/upload" style={{ color: '#93c5fd', alignSelf: 'center' }}>Back to upload</Link>
          <span style={{ color: status?.active ? '#86efac' : '#fcd34d', alignSelf: 'center', fontSize: 13 }}>
            {loading ? 'Loading membership status…' : (status?.active ? 'Membership active' : 'Membership inactive')}
          </span>
        </div>
        {checkoutDisabled ? (
          <p style={{ margin: '10px 0 0', color: '#fca5a5', fontSize: 13 }}>
            Stripe checkout is currently disabled by server config.
          </p>
        ) : null}
        {message ? <p style={{ margin: '10px 0 0', color: '#86efac', fontSize: 13 }}>{message}</p> : null}
        {error ? <p style={{ margin: '10px 0 0', color: '#fca5a5', fontSize: 13 }}>{error}</p> : null}
      </section>

      <section style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#0b1220', overflow: 'hidden' }}>
        <h2 style={{ margin: 0, padding: 12, borderBottom: '1px solid #1f2937' }}>Credits</h2>
        {grouped.credits.map((plan) => {
          const missingProductId = !plan.productId.trim();
          const disabled = checkoutDisabled || missingProductId || busyPlanId === plan.id;
          return (
            <div key={plan.id} style={{ padding: 12, borderBottom: '1px solid #1f2937', display: 'grid', gap: 6 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
                <strong>{plan.name}</strong>
                <span>{plan.amountLabel}</span>
              </div>
              <div style={{ color: '#9ca3af', fontSize: 13 }}>{plan.cadenceLabel} · {plan.categoryLabel}</div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  onClick={() => void startCheckout(plan.id)}
                  disabled={disabled}
                  style={{ borderRadius: 8, border: '1px solid #374151', background: '#111827', color: '#fff', padding: '8px 10px' }}
                >
                  {busyPlanId === plan.id ? 'Opening checkout…' : 'Checkout'}
                </button>
                {missingProductId ? <span style={{ color: '#fca5a5', fontSize: 12 }}>Missing product ID</span> : null}
              </div>
            </div>
          );
        })}
      </section>

      <section style={{ border: '1px solid #1f2937', borderRadius: 12, background: '#0b1220', overflow: 'hidden' }}>
        <h2 style={{ margin: 0, padding: 12, borderBottom: '1px solid #1f2937' }}>Subscriptions</h2>
        {grouped.subscriptions.map((plan) => {
          const missingProductId = !plan.productId.trim();
          const disabled = checkoutDisabled || missingProductId || busyPlanId === plan.id;
          return (
            <div key={plan.id} style={{ padding: 12, borderBottom: '1px solid #1f2937', display: 'grid', gap: 6 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
                <strong>{plan.name}</strong>
                <span>{plan.amountLabel}</span>
              </div>
              <div style={{ color: '#9ca3af', fontSize: 13 }}>{plan.cadenceLabel} · {plan.categoryLabel}</div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  onClick={() => void startCheckout(plan.id)}
                  disabled={disabled}
                  style={{ borderRadius: 8, border: '1px solid #374151', background: '#111827', color: '#fff', padding: '8px 10px' }}
                >
                  {busyPlanId === plan.id ? 'Opening checkout…' : 'Checkout'}
                </button>
                {missingProductId ? <span style={{ color: '#fca5a5', fontSize: 12 }}>Missing product ID</span> : null}
              </div>
            </div>
          );
        })}
      </section>
    </main>
  );
}
