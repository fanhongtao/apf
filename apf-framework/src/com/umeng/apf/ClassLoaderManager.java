package com.umeng.apf;

import android.content.Context;
import com.umeng.apf.util.FieldFinder;

public class ClassLoaderManager {
    public static final int DEFAULT_LOADER = 0;
    public static final int COMMON_LOADER = 1;
    public static final int ANALYTIC_LOADER = 2;
    public static final int UPDATE_LOADER = 3;
    public static final int FEEDBACK_LOADER = 4;
    private static ClassLoaderManager mClassLoaderManager;
    public ClassLoader ORIGINAL_LOADER;
    public ClassLoader CUSTOM_LOADER = null;
    public int STATUS = 0;

    public static ClassLoaderManager getInstance(Context context) {
        if (mClassLoaderManager == null) {
            mClassLoaderManager = new ClassLoaderManager(context);
        }
        return mClassLoaderManager;
    }

    @SuppressWarnings("rawtypes")
    private ClassLoaderManager(Context context) {
        try {
            Context mBase = new FieldFinder<Context>(context.getApplicationContext(), "mBase").get();
            Object mPackageInfo = new FieldFinder(mBase, "mPackageInfo").get();
            FieldFinder<ClassLoader> sClassLoader = new FieldFinder<ClassLoader>(mPackageInfo, "mClassLoader");
            ClassLoader classLoader = sClassLoader.get();
            ORIGINAL_LOADER = classLoader;
            MyClassLoader cl = new MyClassLoader(classLoader);
            sClassLoader.set(cl);
        } catch (NoSuchFieldException e) {
            try {
                throw new ApfException(e);
            } catch (ApfException e1) {
                e1.printStackTrace();
            }
        } catch (IllegalArgumentException e) {
            try {
                throw new ApfException(e);
            } catch (ApfException e1) {
                e1.printStackTrace();
            }
        } catch (IllegalAccessException e) {
            try {
                throw new ApfException(e);
            } catch (ApfException e1) {
                e1.printStackTrace();
            }
        }
    }

    public void setCustomLoader(ClassLoader classLoader) {
        CUSTOM_LOADER = classLoader;
    }

    class MyClassLoader extends ClassLoader {
        public MyClassLoader(ClassLoader parent) {
            super();
        }

        protected Class<?> loadClass(String className, boolean resolve) throws ClassNotFoundException {
            if (ClassLoaderManager.mClassLoaderManager.CUSTOM_LOADER != null) {
                try {
                    if (className.startsWith("com.umeng.common")) {
                        Class<?> class1 = ClassLoaderManager.mClassLoaderManager.CUSTOM_LOADER.loadClass(className);
                        if (class1 != null) {
                            return class1;
                        }
                    }
                    if (className.startsWith("com.umeng.fb")) {
                        Class<?> class1 = ClassLoaderManager.mClassLoaderManager.CUSTOM_LOADER.loadClass(className);
                        if (class1 != null)
                            return class1;
                    }
                } catch (ClassNotFoundException e) {
                    e.printStackTrace();
                }
            }

            return ClassLoaderManager.mClassLoaderManager.ORIGINAL_LOADER.loadClass(className);
        }
    }
}