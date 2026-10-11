import * as AuthSession from 'expo-auth-session';
import * as Crypto from 'expo-crypto';
import { signInWithCustomToken } from 'firebase/auth';
import { httpsCallable } from 'firebase/functions';
import { auth, functions } from './firebase';
import { TERMS_VERSION } from '../config/links';
import {
  MICROSOFT_CLIENT_ID,
  MICROSOFT_ISSUER,
  MICROSOFT_REDIRECT_URI,
} from '../config/microsoft';

// The app drives the whole OAuth code+PKCE flow itself because Firebase's own
// Microsoft provider is unreachable from React Native (its popup/redirect
// methods are web-only, and it rejects a token obtained elsewhere). The
// id_token that comes back is worthless on its own — only the
// `microsoftSignIn` function can turn it into a session, and it verifies the
// signature, audience, issuer and nonce before it does.
//
// Errors are thrown with machine-readable messages for the screen to map onto
// translated text: 'cancelled' (user backed out — not worth showing),
// 'email-exists', 'email-unverified', 'microsoft-failed'.
export async function signInWithMicrosoft(): Promise<void> {
  const discovery = await AuthSession.fetchDiscoveryAsync(MICROSOFT_ISSUER);

  // Fresh per attempt. Microsoft echoes it into the id_token, and the function
  // refuses a token whose nonce doesn't match the one we just sent — that is
  // what stops a token captured from another session being replayed.
  const nonce = Crypto.randomUUID();

  const request = new AuthSession.AuthRequest({
    clientId: MICROSOFT_CLIENT_ID,
    redirectUri: MICROSOFT_REDIRECT_URI,
    scopes: ['openid', 'profile', 'email'],
    responseType: AuthSession.ResponseType.Code,
    usePKCE: true,
    extraParams: { nonce },
  });

  const result = await request.promptAsync(discovery);
  if (result.type === 'cancel' || result.type === 'dismiss') throw new Error('cancelled');
  if (result.type !== 'success' || result.params.error) throw new Error('microsoft-failed');

  const code = result.params.code;
  // Generated inside promptAsync, so it can only be read afterwards.
  const codeVerifier = request.codeVerifier;
  if (!code || !codeVerifier) throw new Error('microsoft-failed');

  const tokens = await AuthSession.exchangeCodeAsync(
    {
      clientId: MICROSOFT_CLIENT_ID,
      code,
      redirectUri: MICROSOFT_REDIRECT_URI,
      extraParams: { code_verifier: codeVerifier },
    },
    discovery,
  );
  if (!tokens.idToken) throw new Error('microsoft-failed');

  const exchange = httpsCallable<
    { idToken: string; nonce: string; termsVersion: string },
    { token: string }
  >(functions, 'microsoftSignIn');

  // TERMS_VERSION travels with the request so the server records which revision
  // the user accepted when it creates their profile.
  const { data } = await exchange({ idToken: tokens.idToken, nonce, termsVersion: TERMS_VERSION });
  await signInWithCustomToken(auth, data.token);
}
