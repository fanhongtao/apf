package com.umeng.apf;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Locale;

import org.json.JSONException;
import org.json.JSONObject;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Environment;
import android.util.DisplayMetrics;
import android.util.Log;

import com.umeng.apf.util.HttpRequest;
import com.umeng.apf.util.MD5;

import dalvik.system.PackageHandler;

public class UPackageHandler extends PackageHandler {
    private static final String TAG = UPackageHandler.class.getName();
    private String mUpdateUrl;
    private String mUmengPubkeyMd5;
    private String mCacheDir;
    private Context mContext;

    public UPackageHandler(Context context) throws ApfException {
        try {
            mContext = context.getApplicationContext();
            StringBuilder urlBuilder = new StringBuilder("http://");
            urlBuilder.append(getString("apf_server"));
            urlBuilder.append(":");
            urlBuilder.append(getString("apf_server_port"));
            urlBuilder.append(getString("apf_server_update_endpoint"));
            mUpdateUrl = urlBuilder.toString();

            mUmengPubkeyMd5 = getString("pub_key_md5");
            mCacheDir = getCacheDir();

            Log.d(TAG, "mUpdateUrl = " + mUpdateUrl);
            Log.d(TAG, "mUmengPubkeyMd5 = " + mUmengPubkeyMd5);
            Log.d(TAG, "mCacheDir = " + mCacheDir);
        } catch (Exception e) {
            Log.e(TAG,
                    "Fatal error, failed to create a UPackageHandler instance, please refer to the detail logcat information. "
                            + System.getProperty("line.separator") + e.getMessage());
            throw new ApfException(e);
        }
    }

    public URL findPackage(String pname) {
        URL cache = getCachedApk(pname);
        if (cache != null) {
            Log.d(TAG, String.format("findPackage(%s), package is hit in the cache.", new Object[] { pname }));

            Log.d(TAG, String.format("findPackage(%s), checking for update asynchoronously.", new Object[] { pname }));
            checkUdateAsync(pname);
            return cache;
        }

        Log.d(TAG, String.format("findPackage(%s), package is not hit in the cache. Try download it from %s",
                new Object[] { pname, mUpdateUrl }));

        return downloadApk(pname);
    }

    private URL downloadApk(String pname) {
        try {
            String body = HttpRequest.get(mUpdateUrl + "?ppn=" + pname).accept("application/json").body();
            JSONObject jObject = new JSONObject(body);
            String downloadUrl = jObject.getString("path");
            if (downloadUrl == null)
                return null;
            File tmpFile = new File(mCacheDir, getCacheFileName(pname) + ".tmp");
            if (tmpFile.exists()) {
                tmpFile.delete();
            }
            HttpRequest.get(downloadUrl).receive(tmpFile);
            File file = new File(mCacheDir, getCacheFileName(pname));

            if (tmpFile.renameTo(file)) {
                return file.toURI().toURL();
            }
            Log.d(TAG, String.format("Failed to rename %s to %s", new Object[] { tmpFile.toString(), file.toString() }));
            return null;
        } catch (HttpRequest.HttpRequestException e) {
            e.printStackTrace();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (JSONException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private void tryLoadApkFromFramework(String pname) throws IOException {
        String fileName = getCacheFileName(pname);
        File dir = new File(mCacheDir);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        File file = new File(dir, fileName + ".tmp");
        if (file.exists()) {
            file.delete();
        }
        file.createNewFile();
        InputStream in = mContext.getAssets().open(fileName);
        FileOutputStream outfile = new FileOutputStream(file);
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = in.read(buffer)) != -1) {
            outfile.write(buffer, 0, bytesRead);
        }
        outfile.flush();
        in.close();
        outfile.close();
        file.renameTo(new File(dir, fileName));
    }

    private void checkUdateAsync(final String pname) {
        new Thread() {
            public void run() {
                UPackageHandler.this.downloadApk(pname);
            }
        }.start();
    }

    private URL getCachedApk(String pname) {
        String fileName = getCacheFileName(pname);
        File file = new File(mCacheDir, fileName);
        if (!file.exists()) {
            Log.d(TAG, pname + " does not exist in cache directory, try load it from framework assests dir.");
            try {
                tryLoadApkFromFramework(pname);
            } catch (IOException e) {
                Log.d(TAG, "tryLoadApkFromFramework(): " + e.getMessage());
            }
        }

        if (!file.exists()) {
            Log.d(TAG, pname + " does not have a local copy.");
            return null;
        }

        URL url = null;
        try {
            url = file.toURI().toURL();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        return url;
    }

    @SuppressLint("NewApi")
    private String getCacheDir() {
        File dir = null;
        String state = Environment.getExternalStorageState();
        if ("mounted".equals(state)) {
            if (Build.VERSION.SDK_INT < 8) {
                dir = Environment.getDownloadCacheDirectory();
            } else {
                dir = mContext.getExternalCacheDir();
            }
        }
        if (dir == null) {
            dir = mContext.getCacheDir();
        }
        if (dir == null)
            return null;
        return dir.toString();
    }

    private static String getCacheFileName(String pname) {
        return Integer.toHexString(pname.hashCode()).toUpperCase(Locale.US) + ".apk";
    }

    public boolean verifyPackage(File apk) {
        try {
            Class<?> class_PackageParser = Class.forName("android.content.pm.PackageParser");
            Class<?> class_Package = Class.forName("android.content.pm.PackageParser$Package");
            Constructor<?> constructor_PackageParser = class_PackageParser.getConstructor(new Class[] { String.class });
            Object parserPackage = constructor_PackageParser.newInstance(new Object[] { apk.getAbsolutePath() });
            DisplayMetrics metrics = new DisplayMetrics();
            metrics.setToDefaults();
            Method method_parsePackage = class_PackageParser.getMethod("parsePackage", new Class[] { File.class,
                    String.class, DisplayMetrics.class, Integer.TYPE });
            Object pkg = method_parsePackage.invoke(parserPackage,
                    new Object[] { apk, mCacheDir, metrics, Integer.valueOf(0) });
            Method method_collectCertificates = class_PackageParser.getMethod("collectCertificates", new Class[] {
                    class_Package, Integer.TYPE });
            boolean suc = ((Boolean) method_collectCertificates.invoke(parserPackage,
                    new Object[] { pkg, Integer.valueOf(0) })).booleanValue();
            Log.d(TAG, "GetKey = " + String.valueOf(suc));
            if (!suc) {
                return suc;
            }

            Field field = class_Package.getDeclaredField("mSignatures");
            field.setAccessible(true);
            Signature[] signatures = (Signature[]) field.get(pkg);

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(
                    signatures[0].toByteArray()));
            String publickey = cert.getPublicKey().toString();
            publickey = getPublicKey(publickey);
            publickey = MD5.getMD5(publickey.getBytes());
            Log.d(TAG, "mUmengPubkeyMd5 = " + publickey);

            if (publickey.equals(mUmengPubkeyMd5)) {
                return true;
            }
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            return true;
        } catch (SecurityException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
            return true;
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (ApfException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private String getPublicKey(String content) {
        String publicKey = null;
        int cut_start = 0;
        int num = 0;
        for (int i = 0; i < content.length(); i++) {
            if (!Character.isLetterOrDigit(content.charAt(i))) {
                if (i - cut_start > num) {
                    publicKey = content.substring(cut_start + 1, i);
                    num = i - cut_start;
                }
                cut_start = i;
            }
        }
        return publicKey;
    }

    private String getString(String key) throws ClassNotFoundException, NoSuchFieldException, IllegalArgumentException,
            IllegalAccessException {
        Class<?> stringClass = Class.forName(mContext.getPackageName() + ".R$string");
        Field field = stringClass.getField(key);
        int id = field.getInt(stringClass);
        return mContext.getString(id);
    }
}