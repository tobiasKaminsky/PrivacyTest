package kaminsky.me.privacytest.utils;

import android.content.Context;
import android.preference.PreferenceManager;

public class PreferencesUtils {
    public final static String KEY_SERVER = "server";
    public final static String KEY_USERNAME = "username";
    public final static String KEY_PASSWORD = "password";

    static public void setString(Context context, String key, String value) {
        PreferenceManager.getDefaultSharedPreferences(context).edit().putString(key, value).apply();
    }

    static public String getString(Context context, String key) {
        return PreferenceManager.getDefaultSharedPreferences(context).getString(key, "");
    }
}
