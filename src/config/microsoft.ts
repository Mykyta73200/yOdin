// Azure app registration for Microsoft sign-in.
//
// The registration is multitenant ("any organizational directory + personal
// Microsoft accounts") and is a public client: there is deliberately no client
// secret, because anything shipped inside an APK can be unpacked out of it.
// PKCE takes the secret's place.
//
// The client ID is not a secret in the cryptographic sense — it travels in
// plain sight in every authorize request — but it is kept out of the
// repository anyway, in .env (gitignored) like the Firebase config, so it is
// handed to collaborators deliberately rather than by cloning. The Cloud
// Function reads the same value from the MICROSOFT_CLIENT_ID secret; the two
// must match, since the function validates it as the token's audience.
// Empty value → the sign-in attempt fails with a plain error rather than
// opening a broken Microsoft page.
export const MICROSOFT_CLIENT_ID = process.env.EXPO_PUBLIC_MICROSOFT_CLIENT_ID ?? '';

// Must match the redirect URI registered in Azure byte for byte, so it is
// written out rather than built with makeRedirectUri() — that helper returns an
// exp:// URL under Expo Go and would silently stop matching.
export const MICROSOFT_REDIRECT_URI = 'app.yodin://auth/microsoft';

// `common` is what lets both personal accounts and every organization in. The
// authorize/token endpoints are read from this issuer's discovery document
// rather than hardcoded.
export const MICROSOFT_ISSUER = 'https://login.microsoftonline.com/common/v2.0';
