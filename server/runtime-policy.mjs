// APNs transport and StoreKit purchase environments are independent.
// A TestFlight lane uses production APNs with Sandbox purchases; keep that lane
// invitation-only and in its own database, never fallback from production proof.
export function runtimePolicy(apns, apple) {
  const environments = ['sandbox', 'production'];
  if (!environments.includes(apns.environment) || !environments.includes(apple.environment)) {
    throw new Error('Explicit APNs and StoreKit environments required');
  }
  return {
    apnsEnvironment: apns.environment,
    purchaseEnvironment: { sandbox: 'Sandbox', production: 'Production' }[apple.environment],
  };
}
