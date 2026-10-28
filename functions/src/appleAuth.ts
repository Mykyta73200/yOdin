import { onCall, HttpsError } from 'firebase-functions/v2/https';
import { defineSecret } from 'firebase-functions/params';
import { getFirestore } from 'firebase-admin/firestore';
import { SignJWT, importPKCS8 } from 'jose';
import { ensureProviderProfile } from './microsoftAuth';

// ── Sign in with Apple: profile + token revocation ───────────────────────────
// The sign-in itself needs no function: an Apple id_token is issued to our
// bundle id, so Firebase verifies it server-side and the app calls
// signInWithCredential directly. What is left is the part the client must not
// be trusted with — creating users/{uid} (the rules demand points == 0) and
// claiming a handle, which Apple never supplies.
//
// The second half is a hard App Store requirement rather than a nicety: an app
// offering Sign in with Apple must revoke the token when the account is
// deleted. Revocation needs a refresh token, which can only be obtained from
// the single-use authorizationCode captured during sign-in — so it is traded
// for one immediately and stored for later.

const db = () => getFirestore();
const REGION = 'europe-west1';

// Contents of the AuthKey_*.p8 created under "Sign in with Apple" at
// developer.apple.com → Keys. Not the App Store Connect API key, which is a
// different key with the same filename shape and cannot sign these requests.
const APPLE_SIWA_KEY = defineSecret('APPLE_SIWA_KEY');
const APPLE_SIWA_KEY_ID = defineSecret('APPLE_SIWA_KEY_ID');
const APPLE_TEAM_ID = defineSecret('APPLE_TEAM_ID');

// For a native app the OAuth client is the bundle identifier itself; a Services
// ID (and the domain verification it drags along) is only needed for the web
// flow, which this app does not use.
const CLIENT_ID = 'app.yodin';
const APPLE_TOKEN_URL = 'https://appleid.apple.com/auth/token';
const APPLE_REVOKE_URL = 'https://appleid.apple.com/auth/revoke';

// Apple authenticates the app by a short-lived JWT signed with the .p8 rather
// than by a static secret, so one is minted per request.
async function clientSecret(): Promise<string> {
  const key = await importPKCS8(APPLE_SIWA_KEY.value().replace(/\n/g, '\n'), 'ES256');
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sub: CLIENT_ID })
    .setProtectedHeader({ alg: 'ES256', kid: APPLE_SIWA_KEY_ID.value() })
    .setIssuer(APPLE_TEAM_ID.value())
    .setAudience('https://appleid.apple.com')
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(key);
}

async function appleForm(url: string, body: Record<string, string>): Promise<Response> {
  return fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ ...body, client_id: CLIENT_ID, client_secret: await clientSecret() }),
  });
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

export const appleEnsureProfile = onCall(
  { region: REGION, secrets: [APPLE_SIWA_KEY, APPLE_SIWA_KEY_ID, APPLE_TEAM_ID] },
  async (request) => {
    const uid = request.auth?.uid;
    if (!uid) throw new HttpsError('unauthenticated', 'sign-in-required');

    // Only a session that actually came from Apple may take this path — without
    // the check any signed-in user could call it and have a profile minted with
    // a name of their choosing.
    if (request.auth?.token?.firebase?.sign_in_provider !== 'apple.com') {
      throw new HttpsError('permission-denied', 'wrong-provider');
    }

    const termsVersion = str(request.data?.termsVersion);
    if (!termsVersion || termsVersion.length > 32) {
      throw new HttpsError('invalid-argument', 'bad-request');
    }

    // Apple hides the real address behind @privaterelay.appleid.com when the
    // user asks it to; either way it is only ever used to seed a handle, never
    // stored (users/{uid} is world-readable).
    const email = str(request.auth?.token?.email) || `${uid}@privaterelay.appleid.com`;
    // Names are capped because they land in a public document; Apple does not
    // bound them and the only other writer of this field is the signup form.
    const firstName = str(request.data?.firstName).slice(0, 40);
    const lastName = str(request.data?.lastName).slice(0, 40);

    const created = await ensureProviderProfile({ uid, email, firstName, lastName }, termsVersion);

    // Best-effort: a user who cannot be revoked later is still better than a
    // user who cannot sign in at all, and the code is useless on a repeat
    // sign-in anyway (Apple only issues it once per authorization).
    const code = str(request.data?.authorizationCode);
    if (code) await storeRefreshToken(uid, code).catch(() => {});

    return { created };
  },
);

// Kept out of users/{uid}, which is world-readable. Nothing in the Firestore
// rules grants access to this collection, so it is reachable only by the Admin
// SDK.
async function storeRefreshToken(uid: string, authorizationCode: string): Promise<void> {
  const res = await appleForm(APPLE_TOKEN_URL, {
    grant_type: 'authorization_code',
    code: authorizationCode,
  });
  if (!res.ok) return;
  const data = (await res.json()) as { refresh_token?: string };
  if (!data.refresh_token) return;
  await db().doc(`appleTokens/${uid}`).set({
    refreshToken: data.refresh_token,
    updatedAt: Date.now(),
  });
}

// Called from account deletion. Apple requires the token to be revoked when the
// account goes away; failing to do so is a review rejection even though sign-in
// itself works fine without it.
export async function revokeAppleToken(uid: string): Promise<void> {
  const ref = db().doc(`appleTokens/${uid}`);
  const snap = await ref.get();
  const token = snap.get('refreshToken') as string | undefined;
  if (!token) return;
  await appleForm(APPLE_REVOKE_URL, {
    token,
    token_type_hint: 'refresh_token',
  }).catch(() => undefined);
  // Dropped regardless of the call's outcome: the account is going away, and a
  // stale refresh token is the one thing that must not outlive it.
  await ref.delete().catch(() => {});
}

export const APPLE_SECRETS = [APPLE_SIWA_KEY, APPLE_SIWA_KEY_ID, APPLE_TEAM_ID];
