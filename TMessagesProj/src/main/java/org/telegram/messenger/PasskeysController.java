package org.telegram.messenger;

import android.content.Context;
import android.util.Base64;

import androidx.annotation.RequiresApi;

import org.json.JSONObject;
import org.telegram.tgnet.ConnectionsManager;
import org.telegram.tgnet.TLObject;
import org.telegram.tgnet.TLRPC;
import org.telegram.tgnet.tl.TL_account;
import org.telegram.ui.ActionBar.AlertDialog;

import java.util.Arrays;

@RequiresApi(api = 28)
public class PasskeysController {

    public static void create(Context context, int currentAccount, Utilities.Callback2<TL_account.Passkey, String> done) {
        if (!BuildVars.SUPPORTS_PASSKEYS) return;

        final AlertDialog progressDialog = new AlertDialog(context, AlertDialog.ALERT_TYPE_SPINNER);
        progressDialog.showDelayed(500);

        ConnectionsManager.getInstance(currentAccount).sendRequestTyped(
            new TL_account.initPasskeyRegistration(),
            AndroidUtilities::runOnUIThread,
            (res, err) -> {
                progressDialog.dismiss();
                if (err != null) {
                    done.run(null, err.text);
                    return;
                }

                final String requestJson;
                try {
                    final JSONObject obj = new JSONObject(res.options.data);
                    final JSONObject publicKeyObj = obj.getJSONObject("publicKey");
                    requestJson = publicKeyObj.toString();
                } catch (Exception e) {
                    FileLog.e(e);
                    done.run(null, e.getMessage());
                    return;
                }

                SoftwarePasskey.register(context, requestJson, (responseJson, error) -> AndroidUtilities.runOnUIThread(() -> {
                    if (responseJson == null) {
                        if ("CANCELLED".equalsIgnoreCase(error)) {
                            done.run(null, "CANCELLED");
                        } else if ("EMPTY".equalsIgnoreCase(error)) {
                            done.run(null, "EMPTY");
                        } else {
                            done.run(null, error);
                        }
                        return;
                    }

                    final TL_account.registerPasskey req2 = new TL_account.registerPasskey();
                    try {
                        final JSONObject json = new JSONObject(responseJson);
                        req2.credential = new TL_account.inputPasskeyCredentialPublicKey();
                        req2.credential.id = json.getString("id");
                        req2.credential.raw_id = json.getString("rawId");

                        final JSONObject response = json.getJSONObject("response");
                        final TL_account.inputPasskeyResponseRegister passkeyResponse = new TL_account.inputPasskeyResponseRegister();
                        passkeyResponse.client_data = new TLRPC.TL_dataJSON();
                        passkeyResponse.client_data.data = new String(Base64.decode(response.getString("clientDataJSON"), Base64.URL_SAFE));
                        passkeyResponse.attestation_object = Base64.decode(response.getString("attestationObject"), Base64.URL_SAFE);

                        if (passkeyResponse.attestation_object.length >= 67 + 16) {
                            FileLog.d("AAGUID: " + bytesToHex(Arrays.copyOfRange(passkeyResponse.attestation_object, 67, 67 + 16)));
                        }

                        req2.credential.response = passkeyResponse;
                    } catch (Exception e) {
                        FileLog.e(e);
                        done.run(null, e.getMessage());
                        return;
                    }

                    final AlertDialog progressDialog2 = new AlertDialog(context, AlertDialog.ALERT_TYPE_SPINNER);
                    progressDialog2.showDelayed(500);

                    final int requestId = ConnectionsManager.getInstance(currentAccount).sendRequestTyped(req2, AndroidUtilities::runOnUIThread, (passkey, err3) -> {
                        progressDialog2.dismiss();
                        if (err3 != null) {
                            done.run(null, err3.text);
                        } else {
                            done.run(passkey, null);
                        }
                    });
                    progressDialog2.setOnCancelListener(d -> {
                        ConnectionsManager.getInstance(currentAccount).cancelRequest(requestId, true);
                        done.run(null, "CANCELLED");
                    });
                }));
            }
        );
    }

    public static Runnable login(Context context, int currentAccount, boolean clickedButton, Utilities.Callback3<Long, TLRPC.auth_Authorization, String> done) {
        return loginInternal(context, currentAccount, null, done);
    }

    public static Runnable loginWithCredentialId(Context context, int currentAccount, String credentialIdB64, Utilities.Callback3<Long, TLRPC.auth_Authorization, String> done) {
        return loginInternal(context, currentAccount, credentialIdB64, done);
    }

    private static Runnable loginInternal(Context context, int currentAccount, String preferredCredentialId, Utilities.Callback3<Long, TLRPC.auth_Authorization, String> done) {
        if (!BuildVars.SUPPORTS_PASSKEYS) return null;

        final boolean[] cancelled = new boolean[1];
        final Runnable[] cancel = new Runnable[1];

        if (!SoftwarePasskey.hasAnyLocalCredential(context)) {
            done.run(0L, null, "EMPTY");
            return () -> cancelled[0] = true;
        }

        if (preferredCredentialId != null) {
            SoftwarePasskey.setForcedCredentialId(preferredCredentialId);
        }

        final TL_account.initPasskeyLogin req = new TL_account.initPasskeyLogin();
        req.api_id = BuildVars.APP_ID;
        req.api_hash = BuildVars.APP_HASH;
        final int requestId = ConnectionsManager.getInstance(currentAccount).sendRequestTyped(req, AndroidUtilities::runOnUIThread, (res, err) -> {
            if (cancelled[0]) return;
            if (err != null) {
                done.run(0L, null, err.text);
                return;
            }

            final String requestJson;
            try {
                final JSONObject obj = new JSONObject(res.options.data);
                final JSONObject publicKeyObj = obj.getJSONObject("publicKey");
                requestJson = publicKeyObj.toString();
            } catch (Exception e) {
                FileLog.e(e);
                done.run(0L, null, e.getMessage());
                return;
            }

            try {
                final Runnable cancelAuth = SoftwarePasskey.authenticate(context, requestJson, (responseJson, error) -> AndroidUtilities.runOnUIThread(() -> {
                    if (cancelled[0]) return;
                    if (responseJson == null) {
                        if ("EMPTY".equalsIgnoreCase(error)) {
                            done.run(0L, null, "EMPTY");
                        } else if ("CANCELLED".equalsIgnoreCase(error)) {
                            done.run(0L, null, "CANCELLED");
                        } else {
                            done.run(0L, null, error);
                        }
                        return;
                    }

                    final int datacenterId;
                    final long userId;

                    final TL_account.finishPasskeyLogin req2 = new TL_account.finishPasskeyLogin();
                    req2.credential = new TL_account.inputPasskeyCredentialPublicKey();

                    try {
                        final JSONObject json = new JSONObject(responseJson);

                        req2.credential.id = json.getString("id");
                        req2.credential.raw_id = json.getString("rawId");

                        final JSONObject response = json.getJSONObject("response");
                        final TL_account.inputPasskeyResponseLogin passkeyResponse = new TL_account.inputPasskeyResponseLogin();
                        passkeyResponse.client_data = new TLRPC.TL_dataJSON();
                        passkeyResponse.client_data.data = new String(Base64.decode(response.getString("clientDataJSON"), Base64.URL_SAFE));

                        passkeyResponse.authenticator_data = Base64.decode(response.getString("authenticatorData"), Base64.URL_SAFE);
                        passkeyResponse.signature = Base64.decode(response.getString("signature"), Base64.URL_SAFE);
                        passkeyResponse.user_handle = new String(Base64.decode(response.getString("userHandle"), Base64.URL_SAFE));

                        datacenterId = Integer.parseInt(passkeyResponse.user_handle.split(":")[0]);
                        userId = Long.parseLong(passkeyResponse.user_handle.split(":")[1]);

                        req2.credential.response = passkeyResponse;
                    } catch (Exception e) {
                        FileLog.e(e);
                        done.run(0L, null, e.getMessage());
                        return;
                    }

                    final AlertDialog progressDialog = new AlertDialog(context, AlertDialog.ALERT_TYPE_SPINNER);
                    progressDialog.showDelayed(500);

                    if (datacenterId != ConnectionsManager.getInstance(currentAccount).getCurrentDatacenterId()) {
                        final int from_dc_id = ConnectionsManager.getInstance(currentAccount).getCurrentDatacenterId();
                        final long from_auth_key_id = ConnectionsManager.getInstance(currentAccount).getCurrentAuthKeyId();

                        ConnectionsManager.getInstance(currentAccount).setDefaultDatacenterId(datacenterId);

                        req2.flags |= TLObject.FLAG_0;
                        req2.from_dc_id = from_dc_id;
                        req2.from_auth_key_id = from_auth_key_id;
                    }

                    final int finishRequestId = ConnectionsManager.getInstance(currentAccount).sendRequestTyped(req2, AndroidUtilities::runOnUIThread, (auth, err3) -> {
                        progressDialog.dismiss();
                        if (err3 != null) {
                            done.run(userId, null, err3.text);
                        } else {
                            done.run(userId, auth, null);
                        }
                    }, datacenterId, ConnectionsManager.RequestFlagWithoutLogin | ConnectionsManager.RequestFlagInvokeAfter);

                    progressDialog.setOnCancelListener(d -> {
                        ConnectionsManager.getInstance(currentAccount).cancelRequest(finishRequestId, true);
                        done.run(userId, null, "CANCELLED");
                    });
                }));
                cancel[0] = cancelAuth;
            } catch (Exception e) {
                done.run(0L, null, e.getMessage());
            }

        }, ConnectionsManager.RequestFlagWithoutLogin);

        cancel[0] = () -> ConnectionsManager.getInstance(currentAccount).cancelRequest(requestId, true);

        return () -> {
            cancelled[0] = true;
            if (cancel[0] != null) {
                cancel[0].run();
            }
        };
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
