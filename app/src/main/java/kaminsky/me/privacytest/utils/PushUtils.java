/*
 * Nextcloud Android client application
 *
 * @author Mario Danic
 * Copyright (C) 2017-2018 Mario Danic
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package kaminsky.me.privacytest.utils;

import android.accounts.AuthenticatorException;
import android.accounts.OperationCanceledException;
import android.content.Context;
import android.net.Uri;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import com.google.firebase.iid.FirebaseInstanceId;
import com.google.gson.Gson;
import com.owncloud.android.lib.common.OwnCloudAccount;
import com.owncloud.android.lib.common.OwnCloudBasicCredentials;
import com.owncloud.android.lib.common.OwnCloudClient;
import com.owncloud.android.lib.common.OwnCloudClientManagerFactory;
import com.owncloud.android.lib.common.OwnCloudCredentials;
import com.owncloud.android.lib.common.operations.RemoteOperation;
import com.owncloud.android.lib.common.operations.RemoteOperationResult;
import com.owncloud.android.lib.resources.notifications.RegisterAccountDeviceForNotificationsOperation;
import com.owncloud.android.lib.resources.notifications.RegisterAccountDeviceForProxyOperation;
import com.owncloud.android.lib.resources.notifications.models.PushResponse;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;

import kaminsky.me.privacytest.datamodel.PushConfigurationState;

public final class PushUtils {

    public static final String KEY_PUSH = "push";
    private static final String TAG = "PushUtils";
    private static final String KEYPAIR_FOLDER = "nc-keypair";
    private static final String KEYPAIR_FILE_NAME = "push_key";
    private static final String KEYPAIR_PRIV_EXTENSION = ".priv";
    private static final String KEYPAIR_PUB_EXTENSION = ".pub";

    private PushUtils() {
    }

    public static String generateSHA512Hash(String pushToken) {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA-512");
            messageDigest.update(pushToken.getBytes());
            return bytesToHex(messageDigest.digest());
        } catch (NoSuchAlgorithmException e) {
            Log.d(TAG, "SHA-512 algorithm not supported");
        }
        return "";
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte individualByte : bytes) {
            result.append(Integer.toString((individualByte & 0xff) + 0x100, 16)
                    .substring(1));
        }
        return result.toString();
    }

    private static int generateRsa2048KeyPair(Context context) {
        String keyPath = context.getFilesDir().getAbsolutePath() + File.separator + KEYPAIR_FOLDER;

        String privateKeyPath = keyPath + File.separator + KEYPAIR_FILE_NAME + KEYPAIR_PRIV_EXTENSION;
        String publicKeyPath = keyPath + File.separator + KEYPAIR_FILE_NAME + KEYPAIR_PUB_EXTENSION;
        File keyPathFile = new File(keyPath);

        if (!new File(privateKeyPath).exists() && !new File(publicKeyPath).exists()) {
            try {
                if (!keyPathFile.exists()) {
                    keyPathFile.mkdir();
                }
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(2048);

                KeyPair pair = keyGen.generateKeyPair();
                int statusPrivate = saveKeyToFile(pair.getPrivate(), privateKeyPath);
                int statusPublic = saveKeyToFile(pair.getPublic(), publicKeyPath);

                if (statusPrivate == 0 && statusPublic == 0) {
                    // all went well
                    return 0;
                } else {
                    return -2;
                }
            } catch (NoSuchAlgorithmException e) {
                Log.d(TAG, "RSA algorithm not supported");
            }
        } else {
            // we already have the key
            return -1;
        }

        // we failed to generate the key
        return -2;
    }

    public static void pushRegistrationToServer(Context context) {
        String token = FirebaseInstanceId.getInstance().getToken();
        String pushServer = "https://push-notifications.nextcloud.com";

        if (!TextUtils.isEmpty(token)) {
            PushUtils.generateRsa2048KeyPair(context);
            String pushTokenHash = PushUtils.generateSHA512Hash(token).toLowerCase(Locale.ROOT);
            PublicKey devicePublicKey = (PublicKey) PushUtils.readKeyFromFile(true, context);

            if (devicePublicKey != null) {
                byte[] publicKeyBytes = Base64.encode(devicePublicKey.getEncoded(), Base64.NO_WRAP);
                String publicKey = new String(publicKeyBytes);
                publicKey = publicKey.replaceAll("(.{64})", "$1\n");

                publicKey = "-----BEGIN PUBLIC KEY-----\n" + publicKey + "\n-----END PUBLIC KEY-----\n";

                String providerValue;
                PushConfigurationState accountPushData;
                Gson gson = new Gson();

                providerValue = PreferencesUtils.getString(context, KEY_PUSH);

                if (!TextUtils.isEmpty(providerValue)) {
                    accountPushData = gson.fromJson(providerValue, PushConfigurationState.class);
                } else {
                    accountPushData = null;
                }

                if (accountPushData != null && !accountPushData.getPushToken().equals(token) &&
                        !accountPushData.isShouldBeDeleted() || TextUtils.isEmpty(providerValue)) {
                    try {
                        Uri uri = Uri.parse(PreferencesUtils.getString(context, PreferencesUtils.KEY_SERVER));
                        String username = PreferencesUtils.getString(context, PreferencesUtils.KEY_USERNAME);
                        String password = PreferencesUtils.getString(context, PreferencesUtils.KEY_PASSWORD);

                        OwnCloudCredentials credentials = new OwnCloudBasicCredentials(username, password);
                        OwnCloudAccount ocAccount = new OwnCloudAccount(uri, credentials);
                        OwnCloudClient mClient = OwnCloudClientManagerFactory.getDefaultSingleton().getClientFor(ocAccount, context);

                        RemoteOperation registerAccountDeviceForNotificationsOperation = new RegisterAccountDeviceForNotificationsOperation(pushTokenHash, publicKey, pushServer);

                        RemoteOperationResult remoteOperationResult = registerAccountDeviceForNotificationsOperation.execute(mClient);

                        if (remoteOperationResult.isSuccess()) {
                            PushResponse pushResponse = remoteOperationResult.getPushResponseData();

                            RemoteOperation registerAccountDeviceForProxyOperation = new
                                    RegisterAccountDeviceForProxyOperation(
                                    pushServer,
                                    token, pushResponse.getDeviceIdentifier(), pushResponse.getSignature(),
                                    pushResponse.getPublicKey());

                            remoteOperationResult = registerAccountDeviceForProxyOperation.execute(mClient);

                            if (remoteOperationResult.isSuccess()) {
                                PushConfigurationState pushArbitraryData = new PushConfigurationState(token,
                                        pushResponse.getDeviceIdentifier(), pushResponse.getSignature(),
                                        pushResponse.getPublicKey(), false);
                                PreferencesUtils.setString(context, KEY_PUSH, gson.toJson(pushArbitraryData));
                            }
                        }
                    } catch (com.owncloud.android.lib.common.accounts.AccountUtils.AccountNotFoundException e) {
                        Log.d(TAG, "Failed to find an account");
                    } catch (AuthenticatorException e) {
                        Log.d(TAG, "Failed via AuthenticatorException");
                    } catch (IOException e) {
                        Log.d(TAG, "Failed via IOException");
                    } catch (OperationCanceledException e) {
                        Log.d(TAG, "Failed via OperationCanceledException");
                    }
                }
            }
        }
    }

    public static Key readKeyFromFile(boolean readPublicKey, Context context) {
        String keyPath = context.getFilesDir().getAbsolutePath() + File.separator + KEYPAIR_FOLDER;

        String privateKeyPath = keyPath + File.separator + KEYPAIR_FILE_NAME + KEYPAIR_PRIV_EXTENSION;
        String publicKeyPath = keyPath + File.separator + KEYPAIR_FILE_NAME + KEYPAIR_PUB_EXTENSION;

        String path;

        if (readPublicKey) {
            path = publicKeyPath;
        } else {
            path = privateKeyPath;
        }

        FileInputStream fileInputStream = null;
        try {
            fileInputStream = new FileInputStream(path);
            byte[] bytes = new byte[fileInputStream.available()];
            fileInputStream.read(bytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            if (readPublicKey) {
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
                return keyFactory.generatePublic(keySpec);
            } else {
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
                return keyFactory.generatePrivate(keySpec);
            }

        } catch (FileNotFoundException e) {
            Log.d(TAG, "Failed to find path while reading the Key");
        } catch (IOException e) {
            Log.d(TAG, "IOException while reading the key");
        } catch (InvalidKeySpecException e) {
            Log.d(TAG, "InvalidKeySpecException while reading the key");
        } catch (NoSuchAlgorithmException e) {
            Log.d(TAG, "RSA algorithm not supported");
        } finally {
            if (fileInputStream != null) {
                try {
                    fileInputStream.close();
                } catch (IOException e) {
                    Log.e(TAG, "Error closing input stream during reading key from file", e);
                }
            }
        }

        return null;
    }

    private static int saveKeyToFile(Key key, String path) {
        byte[] encoded = key.getEncoded();
        FileOutputStream keyFileOutputStream = null;
        try {
            if (!new File(path).exists()) {
                File newFile = new File(path);
                newFile.getParentFile().mkdirs();
                newFile.createNewFile();
            }
            keyFileOutputStream = new FileOutputStream(path);
            keyFileOutputStream.write(encoded);
            return 0;
        } catch (FileNotFoundException e) {
            Log.d(TAG, "Failed to save key to file");
        } catch (IOException e) {
            Log.d(TAG, "Failed to save key to file via IOException");
        } finally {
            if (keyFileOutputStream != null) {
                try {
                    keyFileOutputStream.close();
                } catch (IOException e) {
                    Log.e(TAG, "Error closing input stream during reading key from file", e);
                }
            }
        }

        return -1;
    }

    private static Key readKeyFromString(boolean readPublicKey, String keyString) {
        String modifiedKey;
        if (readPublicKey) {
            modifiedKey = keyString.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----",
                    "").replace("-----END PUBLIC KEY-----", "");
        } else {
            modifiedKey = keyString.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----",
                    "").replace("-----END PRIVATE KEY-----", "");
        }

        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            if (readPublicKey) {
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(modifiedKey, Base64.DEFAULT));
                return keyFactory.generatePublic(keySpec);
            } else {
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(modifiedKey, Base64.DEFAULT));
                return keyFactory.generatePrivate(keySpec);
            }
        } catch (NoSuchAlgorithmException e) {
            Log.d("TAG", "No such algorithm while reading key from string");
        } catch (InvalidKeySpecException e) {
            Log.d("TAG", "Invalid key spec while reading key from string");
        }

        return null;
    }
}
