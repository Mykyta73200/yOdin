import { onCall, HttpsError } from 'firebase-functions/v2/https';
import { defineSecret } from 'firebase-functions/params';
import { getAuth } from 'firebase-admin/auth';
import { getFirestore } from 'firebase-admin/firestore';
import { createRemoteJWKSet, decodeJwt, jwtVerify, type JWTPayload } from 'jose';

// ── Microsoft sign-in ────────────────────────────────────────────────────────
// Firebase Auth refuses `signInWithCredential` for the `microsoft.com` provider
// (its server can't verify the audience of a Microsoft token, which would allow
// replay across projects), and the JS SDK's popup/redirect flows are web-only.
// So the app runs the OAuth code+PKCE flow itself with expo-auth-session and
// hands the resulting id_token here. This function is the only place that
// decides whether that token is real; everything downstream trusts the Firebase
// custom token it returns.
//
// Registered as a multitenant Azure app ("any organizational directory +
// personal Microsoft accounts"), so tokens arrive from arbitrary tenants and
// neither the issuer nor the signing keys are a constant — both are derived
// from the token's own `tid`. That is the step copy-pasted single-tenant
// snippets get wrong.
//
// Getters, not module constants: index.ts calls initializeApp() after this
// module is loaded.
const db = () => getFirestore();
const auth = () => getAuth();

const REGION = 'europe-west1';

// Application (client) ID of the Azure app registration, validated below as the
// token's audience. Not a secret in the cryptographic sense — a mobile OAuth
// client has no secret at all, PKCE replaces it — but kept out of the
// repository all the same, so set it before deploying:
//
//   firebase functions:secrets:set MICROSOFT_CLIENT_ID
//
// The app reads the same value from EXPO_PUBLIC_MICROSOFT_CLIENT_ID in .env.
// They must match, or every token arrives with the wrong audience.
const MICROSOFT_CLIENT_ID = defineSecret('MICROSOFT_CLIENT_ID');

// The tenant every personal Microsoft account (Outlook, Hotmail, Xbox, Skype)
// is issued under. It is a documented constant, unlike work-account tenants.
const PERSONAL_TENANT = '9188040d-6c67-4c5b-b112-36a304b66dad';

// `tid` and `oid` are interpolated into a URL and into the Firebase uid, so
// they are checked against the GUID shape before either use.
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Entra rotates signing keys, and each tenant can publish its own set, so the
// key set is fetched per tenant. jose caches and refreshes behind each handle;
// keeping them in a module-level map means a warm instance reuses the cache.
const jwks = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
function keysFor(tid: string) {
  let set = jwks.get(tid);
  if (!set) {
    set = createRemoteJWKSet(
      new URL(`https://login.microsoftonline.com/${tid}/discovery/v2.0/keys`),
    );
    jwks.set(tid, set);
  }
  return set;
}

function str(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null;
}

// Microsoft emits `xms_edov` as the string "1"/"0" rather than a boolean, so a
// `=== true` check silently fails. It says whether the tenant actually owns the
// domain in the `email` claim — without it a tenant admin can put any address
// on a throwaway account and no cross-tenant check happens (the nOAuth
// takeover, Descope 2023). Personal accounts have no admin and Microsoft
// verifies the address itself, so the claim is not required there.
function emailIsOwned(payload: JWTPayload, tid: string): boolean {
  const edov = payload.xms_edov;
  if (edov === true || edov === 1 || edov === '1') return true;
  return tid === PERSONAL_TENANT;
}

async function verifyMicrosoftToken(idToken: string, nonce: string) {
  // The issuer and key set depend on the token's tenant, so `tid` has to be
  // read before the signature can be checked. Nothing else from this decode is
  // trusted, and the verified payload's `tid` is compared back against it.
  let unverified: JWTPayload;
  try {
    unverified = decodeJwt(idToken);
  } catch {
    throw new HttpsError('invalid-argument', 'bad-token');
  }
  const tid = str(unverified.tid);
  if (!tid || !GUID.test(tid)) throw new HttpsError('invalid-argument', 'bad-token');

  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(idToken, keysFor(tid), {
      issuer: `https://login.microsoftonline.com/${tid}/v2.0`,
      audience: MICROSOFT_CLIENT_ID.value(),
      // Phone clocks drift; a minute of tolerance avoids rejecting fresh
      // tokens outright.
      clockTolerance: 60,
    }));
  } catch {
    throw new HttpsError('unauthenticated', 'bad-token');
  }

  if (str(payload.tid) !== tid) throw new HttpsError('unauthenticated', 'bad-token');
  // Binds the token to this sign-in attempt: without it a token captured from
  // another session for the same app would be replayable here.
  if (str(payload.nonce) !== nonce) throw new HttpsError('unauthenticated', 'bad-token');

  const oid = str(payload.oid);
  if (!oid || !GUID.test(oid)) throw new HttpsError('unauthenticated', 'bad-token');

  const email = str(payload.email)?.toLowerCase();
  if (!email || !email.includes('@')) {
    throw new HttpsError('failed-precondition', 'email-missing');
  }
  if (!emailIsOwned(payload, tid)) {
    throw new HttpsError('failed-precondition', 'email-unverified');
  }

  const given = str(payload.given_name);
  const family = str(payload.family_name);
  const full = str(payload.name) ?? email.split('@')[0];

  return {
    // Identity is keyed on tenant + object id, never on the email: Microsoft's
    // own docs say the email claim is mutable and "isn't guaranteed to be
    // correct", so keying on it would let a foreign tenant admin reach another
    // user's data.
    uid: `ms:${tid}:${oid}`,
    email,
    firstName: given ?? full.split(' ')[0] ?? '',
    lastName: family ?? full.split(' ').slice(1).join(' '),
    displayName: given && family ? `${given} ${family}` : full,
  };
}

// yOdin handles are [a-z0-9_], 3–20 chars (see src/utils/mentions.ts). A
// Microsoft user never types one, so it is derived from the email and
// de-duplicated — the handle is cosmetic and editable later in the profile.
function seedHandle(email: string): string {
  const base = email.split('@')[0].toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 16);
  return base.length >= 3 ? base : `yodin${base}`;
}

async function claimHandle(uid: string, email: string): Promise<string> {
  const base = seedHandle(email);
  for (let attempt = 0; attempt < 12; attempt++) {
    const candidate = attempt === 0
      ? base
      : `${base.slice(0, 16)}${Math.floor(Math.random() * 9000) + 1000}`;
    const ref = db().doc(`usernames/${candidate}`);
    const claimed = await db().runTransaction(async (tx) => {
      if ((await tx.get(ref)).exists) return false;
      tx.set(ref, { uid });
      return true;
    });
    if (claimed) return candidate;
  }
  throw new HttpsError('resource-exhausted', 'handle-unavailable');
}

// The app's own signup writes users/{uid} from the client; a provider sign-in
// has no such step, and the Firestore rules reject a create that omits
// `points == 0` — so without this the user would sign in and then be unable to
// finish onboarding. Written with the Admin SDK, which bypasses the rules.
//
// Also runs for an existing Auth user whose profile is missing (the
// re-registration guard in accountDeletion.ts can remove one), so a returning
// user never lands in that dead end either.
export async function ensureProviderProfile(
  identity: { uid: string; email: string; firstName: string; lastName: string },
  termsVersion: string,
): Promise<boolean> {
  const ref = db().doc(`users/${identity.uid}`);
  if ((await ref.get()).exists) return false;

  const username = await claimHandle(identity.uid, identity.email);
  // Email is deliberately not stored: users/{uid} is world-readable and the
  // address lives in Auth only (same rule as registerUser).
  await ref.set({
    uid: identity.uid,
    firstName: identity.firstName,
    lastName: identity.lastName,
    username,
    nationality: '',
    countryCode: '',
    location: '',
    photoURL: '',
    languages: [],
    points: 0,
    createdAt: Date.now(),
    // The app shows the terms notice directly above the Microsoft button, so
    // the tap that started this flow is the consent being recorded here
    // (GDPR Art. 7(1) wants it evidenced, with the revision it applied to).
    acceptedTermsAt: Date.now(),
    acceptedTermsVersion: termsVersion,
  });
  return true;
}

export const microsoftSignIn = onCall(
  { region: REGION, secrets: [MICROSOFT_CLIENT_ID] },
  async (request) => {
    const idToken = str(request.data?.idToken);
    const nonce = str(request.data?.nonce);
    const termsVersion = str(request.data?.termsVersion);
    if (!idToken || !nonce || !termsVersion || termsVersion.length > 32) {
      throw new HttpsError('invalid-argument', 'bad-request');
    }

    const identity = await verifyMicrosoftToken(idToken, nonce);

    const existing = await auth().getUser(identity.uid).catch((e: unknown) => {
      if ((e as { code?: string }).code === 'auth/user-not-found') return null;
      throw e;
    });

    if (!existing) {
      // Accounts are never merged by email. A tenant admin can put a victim's
      // address on an account they control, so linking on a match would hand
      // over the victim's profile; the app tells the user to sign in with
      // their password instead.
      const clash = await auth().getUserByEmail(identity.email).catch(() => null);
      if (clash) throw new HttpsError('already-exists', 'email-exists');

      await auth().createUser({
        uid: identity.uid,
        email: identity.email,
        // Microsoft already proved the address (checked above), and the
        // Firestore rules gate every write on
        // `request.auth.token.email_verified` — leaving this false would let
        // the user in and then silently block every post and comment.
        emailVerified: true,
        displayName: identity.displayName,
      });
    }

    await ensureProviderProfile(identity, termsVersion);

    return { token: await auth().createCustomToken(identity.uid) };
  },
);
