package dalvik.system;

import android.util.Log;
import com.umeng.apf.ApfException;
import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public final class URLDexClassLoader extends DexClassLoader {
    private static final String TAG = URLDexClassLoader.class.getName();
    private DexClassLoader mClassLoader;
    private List<String> mPackages;
    private PackageHandler mHandler;

    public URLDexClassLoader(String[] packages, ClassLoader parent, String optimizedDirectory, PackageHandler handler)
            throws ApfException {
        super("", optimizedDirectory, null, parent);
        StringBuilder sb = new StringBuilder();
        for (String s : packages) {
            sb.append(s);
            sb.append(";");
        }
        Log.d(TAG, "URLDexClassLoader(" + sb + "," + parent + "," + handler + ")");

        mPackages = new ArrayList<String>();
        for (String p : packages) {
            mPackages.add(p);
        }
        mHandler = handler;
        String dexPath = getDexPath();
        Log.d(TAG, "loading dexPath " + dexPath);
        mClassLoader = new DexClassLoader(dexPath, optimizedDirectory, null, parent);
    }

    public Class<?> loadClass(String name)
            throws ClassNotFoundException
    {
        Class<?> c = mClassLoader.loadClass(name);
        Log.d(TAG, "loadClass(" + name + "), loaded " + c + "(" + c.getClassLoader() + ")");
        return c;
    }

    private String getDexPath() throws ApfException {
        StringBuilder dexPathBuilder = new StringBuilder();
        for (String p : mPackages) {
            Log.d(TAG, "getDexPath: try to find package " + p);
            URL url = mHandler.findPackage(p);
            if (url != null) {
                File apk;
                try {
                    apk = new File(url.toURI());
                } catch (URISyntaxException e) {
                    apk = new File(url.getPath());
                }
                if (!mHandler.verifyPackage(apk)) {
                    throw new ApfException(
                            getClass().getName()
                                    + " failed to verify APK library "
                                    + p
                                    + ". Make sure it is signed by appropriate authority. Please contact developer of plugin \""
                                    + p + "\" for details.");
                }

                Log.d(TAG, "getDexPath: found package " + p + " at " + url);
                dexPathBuilder.append(url.toString());
                dexPathBuilder.append(File.pathSeparator);
            }
        }

        int start = dexPathBuilder.lastIndexOf(File.pathSeparator);
        if (start > 0)
            dexPathBuilder.delete(start, dexPathBuilder.length());
        return dexPathBuilder.toString();
    }

    public void addPackage(String name) {
        throw new UnsupportedOperationException();
    }
}