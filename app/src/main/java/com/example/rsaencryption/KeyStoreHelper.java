package com.example.rsaencryption;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

public class KeyStoreHelper {

    KeyStore keyStore;
    String iv;
    String encryptAESKey;
    private static final String TAG = "KEYSTORE";
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String KEYSTORE_ALIAS = "KEYSTORE_DEMO"; // 設定密鑰的別名
    private static final String AES_MODE = "AES/GCM/NoPadding";
    private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";

    public KeyStoreHelper(Context context) {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            // 利用密鑰別名來判斷是否已存在密鑰
            if (!keyStore.containsAlias(KEYSTORE_ALIAS)) {
                genKeyStoreKey(context);
                genAESKey();
            }

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void genKeyStoreKey(Context context) throws Exception {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            generateRSAKey_AboveApi23();
        } else {
            generateRSAKey_BelowApi23(context);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void generateRSAKey_AboveApi23() throws Exception {
        // 金鑰對生成器
        KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER);

        KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec
                .Builder(KEYSTORE_ALIAS, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT) // 三個聲明分別用來簽名、加密、解密
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512) // 簽名算法，可自行訂定限制
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1) // RSA 填充方式，要讓明文的長度與 RSA KEY 等長
                .build();

        // 初始化金鑰對生成器，產生金鑰對
        keyPairGenerator.initialize(keyGenParameterSpec);
        keyPairGenerator.generateKeyPair();
    }

    private void generateRSAKey_BelowApi23(Context context) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        // 金鑰對生成器
        KeyPairGenerator keyPairGenerator = KeyPairGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER);

        // 創建一個開始和結束的時間，在有效範圍內才會產生金鑰
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 100);

        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(KEYSTORE_ALIAS)
                .setSubject(new X500Principal("CN=" + KEYSTORE_ALIAS)) // 用於生成金鑰對自簽名的主體
                .setSerialNumber(BigInteger.TEN) // 用於生成金鑰對自簽名的序號列
                .setStartDate(start.getTime()) // 訂定有效日期的起始和結束時間
                .setEndDate(end.getTime())
                .build();

        // 初始化密鑰對生成器，產生密鑰對
        keyPairGenerator.initialize(spec);
        keyPairGenerator.generateKeyPair();
    }

    public String encrypt(String plainText) {
        try {
            return encryptAES(plainText);
        } catch (Exception e) {
            Log.d(TAG, Log.getStackTraceString(e));
            return "";
        }
    }
    public String decrypt(String encryptedText) {
        try {
            return decryptAES(encryptedText);
        } catch (Exception e) {
            Log.d(TAG, Log.getStackTraceString(e));
            return "";
        }
    }

    // 產生 AES KEY
    private void genAESKey() throws Exception {
        // Generate AES-Key
        byte[] aesKey = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(aesKey);

        // iv 為初始向量，不同的 iv 加解密後的字串是不同的，加解密都需要相同的 iv
        byte[] generated = secureRandom.generateSeed(12);
        iv = Base64.encodeToString(generated, Base64.DEFAULT);

        // 用 RSA 加密 AES KEY
        encryptAESKey = encryptRSA(aesKey);
    }

    // RSA 加密
    private String encryptRSA(byte[] plainText) throws Exception {
        // 取公鑰
        PublicKey publicKey = keyStore.getCertificate(KEYSTORE_ALIAS).getPublicKey();

        // 加密
        Cipher cipher = Cipher.getInstance(RSA_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encryptedByte = cipher.doFinal(plainText);
        return Base64.encodeToString(encryptedByte, Base64.DEFAULT);
    }

    // RSA 解密
    private byte[] decryptRSA(String encryptedText) throws Exception {
        // 取私鑰
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEYSTORE_ALIAS, null);

        // 解密
        Cipher cipher = Cipher.getInstance(RSA_MODE);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] encryptedBytes = Base64.decode(encryptedText, Base64.DEFAULT);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return decryptedBytes;
    }

    // AES 加密
    private String encryptAES(String plainText) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, getAESKey(), new IvParameterSpec(getIV()));

        // 加密過後的 byte
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        // 將 byte 轉為 Base64 的 string 編碼
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
    }

    // AES 解密
    private String decryptAES(String encryptedText) throws Exception {
        // 將加密過後的 Base64 編碼解碼成 byte
        byte[] decodedBytes = Base64.decode(encryptedText.getBytes(), Base64.DEFAULT);

        // 將解碼過後的 byte 使用 AES 解密
        Cipher cipher = Cipher.getInstance(AES_MODE);
        cipher.init(Cipher.DECRYPT_MODE, getAESKey(), new IvParameterSpec(getIV()));

        return new String(cipher.doFinal(decodedBytes));
    }

    private byte[] getIV() {
        return Base64.decode(iv, Base64.DEFAULT);
    }

    // 取出 AES KEY
    private SecretKeySpec getAESKey() throws Exception {
        String encryptedKey = encryptAESKey;
        byte[] aesKey = decryptRSA(encryptedKey);
        return new SecretKeySpec(aesKey, AES_MODE);
    }
}
