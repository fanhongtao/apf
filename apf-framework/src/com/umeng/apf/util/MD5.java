package com.umeng.apf.util;

import com.umeng.apf.ApfException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5
{
    public static String getMD5(byte[] input)
            throws ApfException
    {
        String md5 = null;
        char[] hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(input);
            byte[] tmps = md.digest();
            char[] str = new char[32];
            for (int i = 0; i < 16; i++) {
                byte tmp = tmps[i];
                str[(2 * i)] = hexDigits[(tmp >> 4 & 0xF)];
                str[(2 * i + 1)] = hexDigits[(tmp & 0xF)];
            }
            md5 = new String(str);
        } catch (NoSuchAlgorithmException e) {
            throw new ApfException(e);
        }
        return md5;
    }
}