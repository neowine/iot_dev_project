package com.example.siamenock.tabactivityexample;

//import org.apache.commons.codec.binary.Base64;
import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
//import javax.crypto.spec.IvParameterSpec;

public class AES256Tool {
    public static final char PADDING_CHAR = '_';
    public static final int ENC_SIZE = 16;
    private static volatile AES256Tool INSTANCE;

    private static byte[] secret_key = hexStringToByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    public static AES256Tool getInstance() {
        if (INSTANCE == null) {
            synchronized (AES256Tool.class) {
                if (INSTANCE == null)
                    INSTANCE = new AES256Tool();
            }
        }
        return INSTANCE;
    }

    private AES256Tool() {

    }

    public void SetKey(String newKey) throws UnsupportedEncodingException {
        SetKey(newKey.getBytes("UTF-8"));
    }

    public void SetKey(byte[] newKey) {
        secret_key = newKey;
    }

    // 암호화
    public String AES_Encode(String str) {
        try {
            str = addPaddingTo16n(str);
            byte[] encrypted = AES_Encode(str.getBytes("UTF-8"));                //
            String ret = Base64.encodeToString(encrypted, Base64.NO_WRAP); 		// change output into stringstr = addPaddingTo16n(str);
            return ret;
            /*byte[] ret_b = new byte[str.length()];
            for(int block = 0; block * ENC_SIZE < str.length(); block++){
                String cut = str.substring(block * ENC_SIZE, (block+1) * ENC_SIZE);
                byte[] cutenc = AES_Encode(cut.getBytes("UTF-8"));
                for(int i = 0; i < ENC_SIZE; i++){
                    ret_b[block * ENC_SIZE + i] = cutenc[i];
                }
            }

            String ret = Base64.encodeToString(ret_b, Base64.NO_WRAP);
            if(ret.charAt(ret.length()-1) == '\n')
                ret = ret.substring(0, ret.length() -1);
            return ret;*/
        } catch (Exception e) {
            java.io.StringWriter errors = new java.io.StringWriter();
            e.printStackTrace(new java.io.PrintWriter(errors));
            return errors.toString();
        }
    }

    public byte[] AES_Encode(byte[] byt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] keyData = Arrays.copyOf(secret_key, 32);

        for (int i = 0; i < keyData.length; i++) {
            keyData[i] = (byte) i;
        }
        SecretKey secureKey = new SecretKeySpec(keyData, "AES");

        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, secureKey);
        return c.doFinal(byt); // encrypted message
        /*
        {   // temp code
            String temp = "";
            for (int i = 0; i < byt.length; i += ENC_SIZE) {
                byte[] part = c.doFinal(Arrays.copyOfRange(byt, i, i + ENC_SIZE));
                temp += new String(part);
            }
            return temp.getBytes();
        }
        */
    }

    // 복호화
    public String AES_Decode(String str) {
        try {
            byte[] data = AES_Decode(Base64.decode(str, Base64.NO_WRAP)); // change input into string
            return delPadding(new String(data, "UTF-8")); // change output into string
        } catch (Exception e){
            java.io.StringWriter errors = new java.io.StringWriter();
            e.printStackTrace(new java.io.PrintWriter(errors));
            return "Decoding error!";
        }
    }

    public byte[] AES_Decode(byte[] byt) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        System.out.println(byteArrayToHexString(byt));
        byte[] keyData = Arrays.copyOf(secret_key, 32);
        SecretKey secureKey = new SecretKeySpec(keyData, "AES");
        Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
        c.init(Cipher.DECRYPT_MODE, secureKey);

        return c.doFinal(byt);
    }

    // utility

    public static String addPaddingTo16n(String str) {
        int more_len = (ENC_SIZE - str.length() % ENC_SIZE) % ENC_SIZE;
        for(int i = 0; i < more_len; i++) {
            str += PADDING_CHAR;
        }
        return str;
    }
    // remove ' ' from end of str
    private static String delPadding(String str) {
        int end = str.length();
        while(1 < end && str.charAt(end-1) == PADDING_CHAR) {
            end--;
        }
        return str.substring(0, end);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static String byteArrayToHexString(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();

        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

}
