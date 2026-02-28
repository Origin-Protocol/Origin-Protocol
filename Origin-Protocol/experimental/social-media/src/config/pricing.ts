export type BillingPlan = {
  id: string;
  name: string;
  description: string;
  amountLabel: string;
  cadenceLabel: string;
  categoryLabel: string;
  mode: 'subscription' | 'payment';
  billingType: 'creator' | 'platform';
  productId: string;
};

export const BILLING_PLANS: BillingPlan[] = [
  {
    id: 'origin-credits-300',
    name: 'Origin Credits - 300',
    description: 'Pack of 300 credits.',
    amountLabel: '$20.00 USD',
    cadenceLabel: 'One-time',
    categoryLabel: 'Downloadable Software - custom - personal use',
    mode: 'payment',
    billingType: 'platform',
    productId: 'prod_U2RqwLIYKk1Qcf',
  },
  {
    id: 'origin-credits-120',
    name: 'Origin Credits - 120',
    description: 'Pack of 120 credits.',
    amountLabel: '$10.00 USD',
    cadenceLabel: 'One-time',
    categoryLabel: 'Downloadable Software - custom - personal use',
    mode: 'payment',
    billingType: 'platform',
    productId: 'prod_U2RqkpdsHa0KK2',
  },
  {
    id: 'origin-credits-50',
    name: 'Origin Credits - 50',
    description: 'Pack of 50 credits.',
    amountLabel: '$5.00 USD',
    cadenceLabel: 'One-time',
    categoryLabel: 'Downloadable Software - custom - personal use',
    mode: 'payment',
    billingType: 'platform',
    productId: 'prod_U2RpZDiyPwSihM',
  },
  {
    id: 'origin-studio-pro-yearly',
    name: 'Origin Studio Pro Yearly',
    description: 'Studio Pro annual subscription.',
    amountLabel: '$180.00 USD',
    cadenceLabel: 'Per year',
    categoryLabel: 'Downloadable Software - custom - personal use',
    mode: 'subscription',
    billingType: 'creator',
    productId: 'prod_U2RnhQh9UQht65',
  },
  {
    id: 'origin-studio-pro-monthly',
    name: 'Origin Studio Pro',
    description: 'Studio Pro monthly subscription.',
    amountLabel: '$19.00 USD',
    cadenceLabel: 'Per month',
    categoryLabel: 'Downloadable Software - custom - personal use',
    mode: 'subscription',
    billingType: 'creator',
    productId: 'prod_U2RmK26Xfl3yAo',
  },
  {
    id: 'metered-billing',
    name: 'Metered Billing',
    description: 'Usage-based plan.',
    amountLabel: '$0.10 USD per 100,000 units',
    cadenceLabel: 'Per month',
    categoryLabel: 'Downloadable Software - custom - personal use',
    mode: 'subscription',
    billingType: 'platform',
    productId: 'prod_U1hxB4m2bjbrs6',
  },
  {
    id: 'three-month',
    name: '3 Month',
    description: 'Three month prepaid term.',
    amountLabel: '$22.50 USD',
    cadenceLabel: 'Every 3 months',
    categoryLabel: 'Preset: Downloadable Software - custom - personal use',
    mode: 'subscription',
    billingType: 'creator',
    productId: 'prod_U1hbhFzBk2OVX5',
  },
  {
    id: 'monthly',
    name: 'Monthly',
    description: 'Monthly preset plan.',
    amountLabel: '$10.00 USD',
    cadenceLabel: 'Per month',
    categoryLabel: 'Preset: Downloadable Software - custom - personal use',
    mode: 'subscription',
    billingType: 'creator',
    productId: 'prod_U1hbyFdL3rniSO',
  },
  {
    id: 'one-month',
    name: '1 Month',
    description: 'Single month preset plan.',
    amountLabel: '$10.00 USD',
    cadenceLabel: 'One-time',
    categoryLabel: 'Preset: Downloadable Software - custom - personal use',
    mode: 'payment',
    billingType: 'creator',
    productId: 'prod_U1hbj2NG5Ima60',
  },
  {
    id: 'six-month',
    name: '6 Month',
    description: 'Six month prepaid term.',
    amountLabel: '$30.00 USD',
    cadenceLabel: 'Every 6 months',
    categoryLabel: 'Preset: Downloadable Software - custom - personal use',
    mode: 'subscription',
    billingType: 'creator',
    productId: 'prod_U1hbMKepXAyVqs',
  },
];

export const DEFAULT_CREATOR_PLAN = {
  productId: BILLING_PLANS.find((plan) => plan.id === 'origin-studio-pro-monthly')?.productId || '',
  mode: 'subscription' as const,
  billingType: 'creator' as const,
  priceMonthlyUsd: 19,
  label: 'Origin Studio Pro',
};
