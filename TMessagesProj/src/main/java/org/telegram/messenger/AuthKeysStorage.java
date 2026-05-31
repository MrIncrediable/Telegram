package org.telegram.messenger;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Persists Telegram MTProto auth keys (the 2048-bit shared secret returned by the server during
 * a normal sign-in) on this device so the user can re-import them later from a saved list rather
 * than re-typing 512 hex characters every time.
 *
 * Auth keys are stored in plain SharedPreferences. This is intentionally a developer / power-user
 * feature and should only be used on a trusted device. If the device falls into someone else's
 * hands, every account whose auth key is saved here is compromised — there is no biometric
 * gate on top of these.
 */
public class AuthKeysStorage {

    private static final String PREFS = "auth_keys_storage";
    private static final String PREF_KEY_LIST = "auth_keys";

    public static class StoredAuthKey {
        public final String id;
        public final int dcId;
        public final long userId;
        public final byte[] authKey;
        public final String label;

        public StoredAuthKey(String id, int dcId, long userId, byte[] authKey, String label) {
            this.id = id;
            this.dcId = dcId;
            this.userId = userId;
            this.authKey = authKey;
            this.label = label;
        }
    }

    public static List<StoredAuthKey> getAll(Context context) {
        final List<StoredAuthKey> out = new ArrayList<>();
        try {
            final SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
            final JSONArray arr = new JSONArray(prefs.getString(PREF_KEY_LIST, "[]"));
            for (int i = 0; i < arr.length(); i++) {
                final JSONObject obj = arr.getJSONObject(i);
                final String hex = obj.getString("authKey");
                final byte[] authKey = Utilities.hexToBytes(hex);
                if (authKey == null || authKey.length != 256) continue;
                out.add(new StoredAuthKey(
                        obj.optString("id", obj.getInt("dcId") + ":" + obj.getLong("userId")),
                        obj.getInt("dcId"),
                        obj.getLong("userId"),
                        authKey,
                        obj.optString("label", "")
                ));
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        return out;
    }

    public static boolean has(Context context) {
        return !getAll(context).isEmpty();
    }

    public static void save(Context context, int dcId, long userId, byte[] authKey, String label) {
        if (authKey == null || authKey.length != 256) return;
        try {
            final SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
            final JSONArray arr = new JSONArray(prefs.getString(PREF_KEY_LIST, "[]"));
            final String id = dcId + ":" + userId;
            final JSONArray out = new JSONArray();
            for (int i = 0; i < arr.length(); i++) {
                final JSONObject obj = arr.getJSONObject(i);
                if (obj.optString("id", obj.getInt("dcId") + ":" + obj.getLong("userId")).equals(id)) continue;
                out.put(obj);
            }
            final JSONObject obj = new JSONObject();
            obj.put("id", id);
            obj.put("dcId", dcId);
            obj.put("userId", userId);
            obj.put("authKey", Utilities.bytesToHex(authKey));
            obj.put("label", label == null ? "" : label);
            out.put(obj);
            prefs.edit().putString(PREF_KEY_LIST, out.toString()).apply();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public static void delete(Context context, String id) {
        try {
            final SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
            final JSONArray arr = new JSONArray(prefs.getString(PREF_KEY_LIST, "[]"));
            final JSONArray out = new JSONArray();
            for (int i = 0; i < arr.length(); i++) {
                final JSONObject obj = arr.getJSONObject(i);
                if (obj.optString("id", obj.getInt("dcId") + ":" + obj.getLong("userId")).equals(id)) continue;
                out.put(obj);
            }
            prefs.edit().putString(PREF_KEY_LIST, out.toString()).apply();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }
}
