package dalvik.system;

import java.io.File;
import java.net.URL;

public abstract class PackageHandler {
    public abstract URL findPackage(String paramString);

    public abstract boolean verifyPackage(File paramFile);
}