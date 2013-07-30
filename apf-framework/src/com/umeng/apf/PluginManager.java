package com.umeng.apf;

import java.util.HashSet;
import java.util.Set;

import android.content.Context;
import android.util.Log;
import dalvik.system.PackageHandler;
import dalvik.system.URLDexClassLoader;

public class PluginManager {
    private static final String TAG = PluginManager.class.getName();
    private static Set<String> pluginRepository = new HashSet<String>();
    private static ClassLoader pluginClassLoader;
    private static boolean registerLock = false;

    public static void registerPlugin(String ppn) throws ApfException {
        Log.d(TAG, "registerPlugin " + ppn);
        if (!registerLock) {
            pluginRepository.add(ppn);
        } else {
            throw new ApfException(
                    "Cannot register the plugin anymore. Please register the plugin before loading plugins. ");
        }
    }

    public static void loadPlugins(Context context) throws ApfException {
        registerLock = true;
        PackageHandler packageHandler = new UPackageHandler(context);
        pluginClassLoader = new URLDexClassLoader((String[]) pluginRepository.toArray(new String[pluginRepository
                .size()]), context.getClassLoader(), context.getDir("dex", 0).getAbsolutePath(), packageHandler);
    }

    public static Object newInstance(String clzName) throws ApfException {
        try {
            Class<?> clz = Class.forName(clzName, false, pluginClassLoader);
            Object instance = clz.newInstance();
            Log.d(TAG, "newProxyInstance(" + clzName + ")=" + instance);
            return instance;
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
            throw new ApfException(e);
        } catch (InstantiationException e) {
            e.printStackTrace();
            throw new ApfException(e);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
            throw new ApfException(e);
        }
    }
}