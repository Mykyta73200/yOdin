import * as AppleAuthentication from 'expo-apple-authentication';
import * as Crypto from 'expo-crypto';
import { OAuthProvider, signInWithCredential, reauthenticateWithCredential } from 'firebase/auth';
import { httpsCallable } from 'firebase/functions';
import { auth, functions } from './firebase';
import { TERMS_VERSION } from '../config/links';

// ── Sign in with Apple ───────────────────────────────────────────────────────
// Unlike the Microsoft path, the token exchange happens inside Firebase: an
// Apple id_token is issued to our bundle id, which Firebase's server can verify
// on its own, so `signInWithCredential` is enough and no Cloud Function stands
// in the middle. Apple sign-in is mandatory on iOS because the app already
// offers Microsoft sign-in (App Store guideline 4.8).
//
// Errors are thrown with machine-readable messages for the screen to map onto
// translated text: 'cancelled' (user backed out — not worth showing),
// 'unavailable', 'apple-failed'.

// iOS 13+ only. Android and the Expo Go web build have no Apple button at all,
// so the screen hides it rather than showing one that cannot work.
export function isAppleSignInAvailable(): Promise<boolean> {
  return AppleAuthentication.isAvailableAsync();
}

interface AppleIdentity {
  firebaseCredential: ReturnType<OAuthProvider['credential']>;
  firstName: string;
  lastName: string;
  authorizationCode: string;
}

// Shared by sign-in and by the re-authentication that account deletion needs.
async function requestAppleIdentity(): Promise<AppleIdentity> {
  // Apple is handed the SHA-256 of the nonce and echoes it into the id_token;
  // Firebase is handed the raw value and checks that it hashes to what the
  // token carries. That is what stops a token captured elsewhere being
  // replayed, and it is the step that silently breaks if the same string is
  // sent to both.
  const rawNonce = Crypto.randomUUID();
  const hashedNonce = await Crypto.digestStringAsync(
    Crypto.CryptoDigestAlgorithm.SHA256,
    rawNonce,
  );

  let credential: AppleAuthentication.AppleAuthenticationCredential;
  try {
    credential = await AppleAuthentication.signInAsync({
      requestedScopes: [
        AppleAuthentication.AppleAuthenticationScope.FULL_NAME,
        AppleAuthentication.AppleAuthenticationScope.EMAIL,
      ],
      nonce: hashedNonce,
    });
  } catch (e) {
    // Backing out of the system sheet is not a failure worth a red line.
    if ((e as { code?: string }).code === 'ERR_REQUEST_CANCELED') throw new Error('cancelled');
    throw new Error('apple-failed');
  }

  if (!credential.identityToken) throw new Error('apple-failed');

  // Apple returns the name and email ONLY on the very first sign-in, and null
  // on every one after it. They are therefore read now and sent straight to
  // the server: there is no second chance to recover them, which is why the
  // profile cannot be deferred to a later onboarding step.
  const firstName = credential.fullName?.givenName?.trim() ?? '';
  const lastName = credential.fullName?.familyName?.trim() ?? '';

  return {
    firebaseCredential: new OAuthProvider('apple.com').credential({
      idToken: credential.identityToken,
      rawNonce,
    }),
    firstName,
    lastName,
    authorizationCode: credential.authorizationCode ?? '',
  };
}

export async function signInWithApple(): Promise<void> {
  if (!(await AppleAuthentication.isAvailableAsync())) throw new Error('unavailable');

  const { firebaseCredential, firstName, lastName, authorizationCode } =
    await requestAppleIdentity();
  await signInWithCredential(auth, firebaseCredential);

  // The app's own signup writes users/{uid} from the client, but a provider
  // sign-in has no such step and the Firestore rules reject a create that omits
  // `points == 0` — so the profile (and the handle, which Apple never supplies)
  // is created server-side, exactly as it is for Microsoft.
  //
  // authorizationCode is single-use and short-lived: the server trades it for a
  // refresh token now, because Apple requires the token to be revoked when the
  // account is deleted and that is impossible to do after the fact.
  const ensure = httpsCallable<
    { firstName: string; lastName: string; authorizationCode: string; termsVersion: string },
    { created: boolean }
  >(functions, 'appleEnsureProfile');

  // A failure here would leave the user signed in with no profile, which the
  // app has no screen for — so the session is dropped and the error surfaces,
  // letting them simply try again.
  try {
    await ensure({ firstName, lastName, authorizationCode, termsVersion: TERMS_VERSION });
  } catch (e) {
    await auth.signOut().catch(() => {});
    throw new Error('apple-failed');
  }
}

// An Apple account has no password, so account deletion cannot ask for one. The
// system sheet is the second factor instead: it refreshes `auth_time`, which is
// what the deleteAccount function checks before it will touch anything.
export async function reauthenticateWithApple(): Promise<void> {
  const user = auth.currentUser;
  if (!user) throw new Error('not-signed-in');
  const { firebaseCredential, authorizationCode } = await requestAppleIdentity();
  await reauthenticateWithCredential(user, firebaseCredential);

  // Hand the fresh code over before deletion runs, so the refresh token Apple's
  // revocation needs is certain to be on file. The one captured at sign-in is
  // best-effort and may never have been stored; without it the revoke call
  // silently does nothing, which is exactly what App Review checks for. The
  // server leaves an existing profile untouched, so the empty names are inert.
  if (authorizationCode) {
    const ensure = httpsCallable<
      { firstName: string; lastName: string; authorizationCode: string; termsVersion: string },
      { created: boolean }
    >(functions, 'appleEnsureProfile');
    await ensure({
      firstName: '',
      lastName: '',
      authorizationCode,
      termsVersion: TERMS_VERSION,
    }).catch(() => undefined);
  }
}
