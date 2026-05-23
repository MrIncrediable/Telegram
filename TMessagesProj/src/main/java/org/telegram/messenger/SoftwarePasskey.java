package org.telegram.messenger;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import org.json.JSONArray;
import org.json.JSONObject;
import org.telegram.ui.LaunchActivity;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.util.concurrent.Executor;

/**
 * Software WebAuthn / passkey implementation that bypasses Android's CredentialManager
 * Digital Asset Links check. Uses Android Keystore for biometric-bound EC P-256 keys and
 * BiometricPrompt for user verification.
 *
 * Keys live in this device's Keystore only - passkeys created here are not synced and do not
 * participate in cross-device (caBLE) sign-in. The wire format to Telegram's server is
 * indistinguishable from a "none"-attestation passkey emitted by any other password manager
 * (Bitwarden / 1Password / Google Password Manager).
 */
public class SoftwarePasskey {

    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String KEY_ALIAS_PREFIX = "tg_passkey_";
    private static final String PREFS = "software_passkeys";
    private static final String PREF_KEY_IDS = "credential_ids";
    private static final String PREF_KEY_USERHANDLE = "uh_";

    public interface Callback {
        void onResult(String responseJson, String error);
    }

    @RequiresApi(api = 28)
    public static void register(Context context, String optionsJson, Callback callback) {
        AndroidUtilities.runOnUIThread(() -> {
            try {
                final JSONObject publicKey = new JSONObject(optionsJson);
                final JSONObject rp = publicKey.getJSONObject("rp");
                final JSONObject user = publicKey.getJSONObject("user");
                final String rpId = rp.getString("id");
                final String challengeB64 = publicKey.getString("challenge");
                final String userIdB64 = user.getString("id");

                if (!canUseBiometrics(context)) {
                    callback.onResult(null, "Biometric authentication is not available on this device");
                    return;
                }

                final byte[] credentialId = new byte[16];
                new SecureRandom().nextBytes(credentialId);
                final String credentialIdB64 = base64Url(credentialId);
                final String alias = KEY_ALIAS_PREFIX + credentialIdB64;

                final KeyPair keyPair = generateKeyPair(alias);
                final ECPublicKey ecPub = (ECPublicKey) keyPair.getPublic();
                final ECPoint w = ecPub.getW();
                final byte[] x = coord32(w.getAffineX());
                final byte[] y = coord32(w.getAffineY());

                final byte[] cosePublicKey = encodeCoseEcPublicKey(x, y);
                final byte[] rpIdHash = sha256(rpId.getBytes(StandardCharsets.UTF_8));
                final byte[] authData = buildAuthenticatorDataWithCredential(
                        rpIdHash,
                        /* flags */ (byte) 0x45, // UP | UV | AT
                        /* signCount */ 0,
                        credentialId,
                        cosePublicKey
                );

                final String clientDataJson = buildClientDataJson("webauthn.create", challengeB64, rpId);
                final byte[] clientDataJsonBytes = clientDataJson.getBytes(StandardCharsets.UTF_8);
                final byte[] attestationObject = buildAttestationObjectNone(authData);

                persistCredentialId(context, credentialIdB64, userIdB64);

                promptBiometricConfirm(context, LocaleController.getString(R.string.PasskeyFeature1Title), (ok, error) -> {
                    if (!ok) {
                        deleteKey(alias);
                        removeCredentialId(context, credentialIdB64);
                        callback.onResult(null, error == null ? "CANCELLED" : error);
                        return;
                    }
                    try {
                        final JSONObject response = new JSONObject();
                        response.put("clientDataJSON", base64Url(clientDataJsonBytes));
                        response.put("attestationObject", base64Url(attestationObject));
                        response.put("transports", new JSONArray().put("internal"));

                        final JSONObject root = new JSONObject();
                        root.put("id", credentialIdB64);
                        root.put("rawId", credentialIdB64);
                        root.put("type", "public-key");
                        root.put("response", response);
                        root.put("authenticatorAttachment", "platform");
                        root.put("clientExtensionResults", new JSONObject());

                        callback.onResult(root.toString(), null);
                    } catch (Exception e) {
                        FileLog.e(e);
                        deleteKey(alias);
                        removeCredentialId(context, credentialIdB64);
                        callback.onResult(null, e.getMessage());
                    }
                });
            } catch (Exception e) {
                FileLog.e(e);
                callback.onResult(null, e.getMessage());
            }
        });
    }

    @RequiresApi(api = 28)
    public static Runnable authenticate(Context context, String optionsJson, Callback callback) {
        final boolean[] cancelled = new boolean[]{ false };
        AndroidUtilities.runOnUIThread(() -> {
            if (cancelled[0]) return;
            try {
                final JSONObject publicKey = new JSONObject(optionsJson);
                final String rpId = publicKey.optString("rpId", "");
                final String challengeB64 = publicKey.getString("challenge");

                String matchedIdStr = null;
                String matchedUserHandle = null;

                if (publicKey.has("allowCredentials")) {
                    final JSONArray allow = publicKey.getJSONArray("allowCredentials");
                    for (int i = 0; i < allow.length(); i++) {
                        final JSONObject c = allow.getJSONObject(i);
                        final byte[] id = base64UrlDecode(c.getString("id"));
                        final String idStr = base64Url(id);
                        if (keystoreContains(KEY_ALIAS_PREFIX + idStr)) {
                            matchedIdStr = idStr;
                            matchedUserHandle = loadUserHandle(context, idStr);
                            break;
                        }
                    }
                }
                if (matchedIdStr == null) {
                    final SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
                    final JSONArray ids = new JSONArray(prefs.getString(PREF_KEY_IDS, "[]"));
                    for (int i = 0; i < ids.length(); i++) {
                        final String idStr = ids.getString(i);
                        if (keystoreContains(KEY_ALIAS_PREFIX + idStr)) {
                            matchedIdStr = idStr;
                            matchedUserHandle = loadUserHandle(context, idStr);
                            break;
                        }
                    }
                }
                if (matchedIdStr == null) {
                    callback.onResult(null, "EMPTY");
                    return;
                }
                final String credentialIdStr = matchedIdStr;
                final String userHandleB64 = matchedUserHandle;
                final String alias = KEY_ALIAS_PREFIX + credentialIdStr;
                final byte[] credentialId = base64UrlDecode(credentialIdStr);

                final byte[] rpIdHash = sha256(rpId.getBytes(StandardCharsets.UTF_8));
                final byte[] authenticatorData = buildAuthenticatorDataNoCredential(
                        rpIdHash,
                        /* flags */ (byte) 0x05, // UP | UV
                        /* signCount */ 0
                );
                final String clientDataJson = buildClientDataJson("webauthn.get", challengeB64, rpId);
                final byte[] clientDataJsonBytes = clientDataJson.getBytes(StandardCharsets.UTF_8);
                final byte[] clientDataHash = sha256(clientDataJsonBytes);
                final byte[] signedData = concat(authenticatorData, clientDataHash);

                final Signature signature;
                try {
                    final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
                    keyStore.load(null);
                    final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
                    if (privateKey == null) {
                        callback.onResult(null, "Key not found");
                        return;
                    }
                    signature = Signature.getInstance("SHA256withECDSA");
                    signature.initSign(privateKey);
                } catch (Exception e) {
                    FileLog.e(e);
                    callback.onResult(null, e.getMessage());
                    return;
                }

                promptBiometricSign(context, LocaleController.getString(R.string.PasskeyFeatureButton), signature, signedData, (sigBytes, error) -> {
                    if (cancelled[0]) return;
                    if (sigBytes == null) {
                        callback.onResult(null, error == null ? "CANCELLED" : error);
                        return;
                    }
                    try {
                        final JSONObject response = new JSONObject();
                        response.put("clientDataJSON", base64Url(clientDataJsonBytes));
                        response.put("authenticatorData", base64Url(authenticatorData));
                        response.put("signature", base64Url(sigBytes));
                        response.put("userHandle", userHandleB64 == null ? "" : userHandleB64);

                        final JSONObject root = new JSONObject();
                        root.put("id", credentialIdStr);
                        root.put("rawId", credentialIdStr);
                        root.put("type", "public-key");
                        root.put("response", response);
                        root.put("authenticatorAttachment", "platform");
                        root.put("clientExtensionResults", new JSONObject());

                        callback.onResult(root.toString(), null);
                    } catch (Exception e) {
                        FileLog.e(e);
                        callback.onResult(null, e.getMessage());
                    }
                });
            } catch (Exception e) {
                FileLog.e(e);
                callback.onResult(null, e.getMessage());
            }
        });

        return () -> cancelled[0] = true;
    }

    public static boolean hasAnyLocalCredential(Context context) {
        try {
            final SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
            final JSONArray ids = new JSONArray(prefs.getString(PREF_KEY_IDS, "[]"));
            for (int i = 0; i < ids.length(); i++) {
                if (keystoreContains(KEY_ALIAS_PREFIX + ids.getString(i))) {
                    return true;
                }
            }
        } catch (Exception ignored) { }
        return false;
    }

    @RequiresApi(api = 28)
    public static boolean canUseBiometrics(Context context) {
        try {
            final BiometricManager manager = BiometricManager.from(context);
            return manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    == BiometricManager.BIOMETRIC_SUCCESS;
        } catch (Exception ignored) {
            return false;
        }
    }

    // region Key & signature plumbing

    @RequiresApi(api = 28)
    private static KeyPair generateKeyPair(String alias) throws Exception {
        final KeyGenParameterSpec.Builder b = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
        } else {
            b.setUserAuthenticationValidityDurationSeconds(-1);
        }
        if (Build.VERSION.SDK_INT >= 24) {
            b.setInvalidatedByBiometricEnrollment(true);
        }
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER);
        kpg.initialize(b.build());
        return kpg.generateKeyPair();
    }

    private static boolean keystoreContains(String alias) {
        try {
            final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);
            return keyStore.containsAlias(alias);
        } catch (Exception e) {
            FileLog.e(e);
            return false;
        }
    }

    private static void deleteKey(String alias) {
        try {
            final KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias);
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    // endregion

    // region Persistence

    private static void persistCredentialId(Context context, String credentialIdB64, String userHandleB64) {
        try {
            final SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
            final JSONArray ids = new JSONArray(prefs.getString(PREF_KEY_IDS, "[]"));
            boolean exists = false;
            for (int i = 0; i < ids.length(); i++) {
                if (credentialIdB64.equals(ids.getString(i))) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                ids.put(credentialIdB64);
            }
            prefs.edit()
                    .putString(PREF_KEY_IDS, ids.toString())
                    .putString(PREF_KEY_USERHANDLE + credentialIdB64, userHandleB64)
                    .apply();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private static void removeCredentialId(Context context, String credentialIdB64) {
        try {
            final SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
            final JSONArray ids = new JSONArray(prefs.getString(PREF_KEY_IDS, "[]"));
            final JSONArray out = new JSONArray();
            for (int i = 0; i < ids.length(); i++) {
                if (!credentialIdB64.equals(ids.getString(i))) {
                    out.put(ids.getString(i));
                }
            }
            prefs.edit()
                    .putString(PREF_KEY_IDS, out.toString())
                    .remove(PREF_KEY_USERHANDLE + credentialIdB64)
                    .apply();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    private static String loadUserHandle(Context context, String credentialIdB64) {
        final SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        return prefs.getString(PREF_KEY_USERHANDLE + credentialIdB64, null);
    }

    // endregion

    // region Biometric prompt

    private interface ConfirmCallback {
        void run(boolean success, String error);
    }

    private interface SignCallback {
        void run(byte[] signatureBytes, String error);
    }

    @RequiresApi(api = 28)
    private static void promptBiometricConfirm(Context context, String title, ConfirmCallback cb) {
        final LaunchActivity activity = LaunchActivity.instance;
        if (activity == null) {
            cb.run(false, "No activity");
            return;
        }
        final Executor executor = ContextCompat.getMainExecutor(context);
        final BiometricPrompt prompt = new BiometricPrompt(activity, executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                FileLog.d("SoftwarePasskey confirm error " + errorCode + " " + errString);
                cb.run(false, errString != null ? errString.toString() : "CANCELLED");
            }

            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                cb.run(true, null);
            }

            @Override
            public void onAuthenticationFailed() {
                FileLog.d("SoftwarePasskey confirm failed");
            }
        });
        final BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setNegativeButtonText(LocaleController.getString(R.string.Cancel))
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build();
        prompt.authenticate(info);
    }

    @RequiresApi(api = 28)
    private static void promptBiometricSign(
            Context context,
            String title,
            Signature signature,
            byte[] dataToSign,
            SignCallback cb
    ) {
        final LaunchActivity activity = LaunchActivity.instance;
        if (activity == null) {
            cb.run(null, "No activity");
            return;
        }
        final Executor executor = ContextCompat.getMainExecutor(context);
        final BiometricPrompt prompt = new BiometricPrompt(activity, executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                FileLog.d("SoftwarePasskey sign error " + errorCode + " " + errString);
                cb.run(null, errString != null ? errString.toString() : "CANCELLED");
            }

            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                try {
                    final BiometricPrompt.CryptoObject crypto = result.getCryptoObject();
                    final Signature unlocked = crypto != null ? crypto.getSignature() : signature;
                    unlocked.update(dataToSign);
                    final byte[] sig = unlocked.sign();
                    cb.run(sig, null);
                } catch (Exception e) {
                    FileLog.e(e);
                    cb.run(null, e.getMessage());
                }
            }

            @Override
            public void onAuthenticationFailed() {
                FileLog.d("SoftwarePasskey sign failed");
            }
        });
        final BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setNegativeButtonText(LocaleController.getString(R.string.Cancel))
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build();
        prompt.authenticate(info, new BiometricPrompt.CryptoObject(signature));
    }

    // endregion

    // region WebAuthn payload builders

    private static byte[] buildAuthenticatorDataWithCredential(
            byte[] rpIdHash,
            byte flags,
            int signCount,
            byte[] credentialId,
            byte[] cosePublicKey
    ) throws Exception {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(rpIdHash);
        out.write(flags);
        out.write((signCount >>> 24) & 0xFF);
        out.write((signCount >>> 16) & 0xFF);
        out.write((signCount >>> 8) & 0xFF);
        out.write(signCount & 0xFF);
        // AAGUID (16 bytes) - all zeros
        out.write(new byte[16]);
        out.write((credentialId.length >>> 8) & 0xFF);
        out.write(credentialId.length & 0xFF);
        out.write(credentialId);
        out.write(cosePublicKey);
        return out.toByteArray();
    }

    private static byte[] buildAuthenticatorDataNoCredential(
            byte[] rpIdHash,
            byte flags,
            int signCount
    ) throws Exception {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(rpIdHash);
        out.write(flags);
        out.write((signCount >>> 24) & 0xFF);
        out.write((signCount >>> 16) & 0xFF);
        out.write((signCount >>> 8) & 0xFF);
        out.write(signCount & 0xFF);
        return out.toByteArray();
    }

    /**
     * COSE_Key for EC P-256 / ES256 (RFC 8152):
     *   1 (kty)=2 EC2, 3 (alg)=-7 ES256, -1 (crv)=1 P-256, -2 (x)=32B, -3 (y)=32B
     */
    private static byte[] encodeCoseEcPublicKey(byte[] x, byte[] y) throws Exception {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xA5);                  // map(5)
        out.write(0x01); out.write(0x02); // 1: 2
        out.write(0x03); out.write(0x26); // 3: -7
        out.write(0x20); out.write(0x01); // -1: 1
        out.write(0x21);                  // -2:
        out.write(0x58); out.write(0x20); // bytes(32)
        out.write(x);
        out.write(0x22);                  // -3:
        out.write(0x58); out.write(0x20); // bytes(32)
        out.write(y);
        return out.toByteArray();
    }

    /**
     * "none"-format attestation object: { "fmt": "none", "attStmt": {}, "authData": <bytes> }
     */
    private static byte[] buildAttestationObjectNone(byte[] authData) throws Exception {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xA3);                                  // map(3)

        out.write(0x63); out.write('f'); out.write('m'); out.write('t');
        out.write(0x64); out.write('n'); out.write('o'); out.write('n'); out.write('e');

        out.write(0x67);
        out.write('a'); out.write('t'); out.write('t'); out.write('S'); out.write('t'); out.write('m'); out.write('t');
        out.write(0xA0);

        out.write(0x68);
        out.write('a'); out.write('u'); out.write('t'); out.write('h'); out.write('D'); out.write('a'); out.write('t'); out.write('a');
        writeCborByteString(out, authData);

        return out.toByteArray();
    }

    private static void writeCborByteString(ByteArrayOutputStream out, byte[] data) {
        final int len = data.length;
        if (len <= 23) {
            out.write(0x40 | len);
        } else if (len <= 0xFF) {
            out.write(0x58);
            out.write(len);
        } else if (len <= 0xFFFF) {
            out.write(0x59);
            out.write((len >>> 8) & 0xFF);
            out.write(len & 0xFF);
        } else {
            out.write(0x5A);
            out.write((len >>> 24) & 0xFF);
            out.write((len >>> 16) & 0xFF);
            out.write((len >>> 8) & 0xFF);
            out.write(len & 0xFF);
        }
        out.write(data, 0, data.length);
    }

    private static String buildClientDataJson(String type, String challengeB64, String rpId) throws Exception {
        // Origin is the canonical web origin for the rpId. Telegram's server validates the
        // assertion against the rp.id it returned, and most server implementations accept the
        // matching "https://<rpId>" origin for non-browser clients.
        final JSONObject obj = new JSONObject();
        obj.put("type", type);
        obj.put("challenge", challengeB64);
        obj.put("origin", "https://" + rpId);
        obj.put("crossOrigin", false);
        return obj.toString();
    }

    // endregion

    // region Encoding helpers

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] coord32(BigInteger n) {
        final byte[] raw = n.toByteArray();
        if (raw.length == 32) return raw;
        final byte[] out = new byte[32];
        if (raw.length < 32) {
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        } else {
            // Leading sign byte (raw.length == 33)
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        }
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        final byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String base64Url(byte[] data) {
        return Base64.encodeToString(data, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
    }

    private static byte[] base64UrlDecode(String s) {
        return Base64.decode(s, Base64.URL_SAFE);
    }

    // endregion

    private SoftwarePasskey() { }
}
