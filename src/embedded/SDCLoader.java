package embedded;
import android.app.Application;
import android.content.Context;
import android.widget.Toast;

import org.json.JSONObject;

import dalvik.system.InMemoryDexClassLoader;
import fj.data.Array;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.DataOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Timer;

// This class will be injected into the APK to be used for decrypting and loading self-decrypting code
public class SDCLoader {

    public static Map<String, String> block_counter = new HashMap<String, String>();
    public static boolean scheduler_started = false;
    public static Context Context = getContext();
    public static String app_id;

    public static boolean match(Object o, byte[] hash) {
        log("Comparing instance of " + o.getClass().getCanonicalName() + " with hash " + Arrays.toString(hash));
        //return Arrays.equals(getHash(o, Arrays.copyOfRange(hash, 0,32)), Arrays.copyOfRange(hash, 32,64));
        return Arrays.equals(getHash(o, Arrays.copyOfRange(hash, 0,32)), Arrays.copyOfRange(hash, 32,52)); // for Sha1
    }

    public static byte[] serialize(Object o) {
        byte[] b;

        if (o instanceof Integer) {
            b = ByteBuffer.allocate(4).putInt((Integer)o).array();
        } else if (o instanceof Byte) {
            b = ByteBuffer.allocate(4).putInt((Byte) o).array();
        } else if (o instanceof Short) {
            b = ByteBuffer.allocate(4).putInt((Short) o).array();
        } else if (o instanceof Long) {
            b = ByteBuffer.allocate(8).putLong((Long) o).array();
        } else if (o instanceof Float) {
            b = ByteBuffer.allocate(4).putFloat((Float) o).array();
        } else if (o instanceof Double) {
            b = ByteBuffer.allocate(8).putDouble(((Double) o)).array();
        } else if (o instanceof Character) {
            b = ByteBuffer.allocate(4).putInt((Character) o).array();
        } else if (o instanceof Boolean) {
            b = ByteBuffer.allocate(4).putInt(((Boolean) o) ? 1 : 0).array();
        } else if (o instanceof String) {
            log("Serializing string value " + o);
            b = ((String)o).getBytes();
        } else if (o instanceof Class) {
            log("Serializing class name " + ((Class) o).getCanonicalName());
            b = ((Class) o).getCanonicalName().getBytes();
        } else if (o instanceof Type) {
            // TODO: Tested - leads to not found  getTypeName([])
//            log("Serializing java.lang.reflect.Type name " + ((Type) o).getTypeName());
//            b = ((Type) o).getTypeName().getBytes();
	        return null;
	} else {
            log("Tried to serialize invalid object. RETURNING NULL!");
            return null;
        }
        return b;
    }


    public static byte[] getHash(Object o, byte[] salt) {
        return getHash1(o, salt, "SHA-1");
    }

    public static byte[] getHash1(Object o, byte[] salt, String hashInstance) {
        MessageDigest d = null;
        try{
            d = MessageDigest.getInstance(hashInstance);
        } catch (Exception ignored){} //TODO: Can we just ignore exceptions in Jimple instead?
        d.update(salt);
        d.update(serialize(o));
        return d.digest();
    }

    public static byte[] getHash(Object o, String hashInstance) {
        MessageDigest d = null;
        try{
            d = MessageDigest.getInstance(hashInstance);
        } catch (Exception ignored){} //TODO: Can we just ignore exceptions in Jimple instead?
        d.update(serialize(o));
        return d.digest();
    }

    public static String get_package_name() // Get package ID of the application
    {
        if (Context==null){
            Context = getContext();
            app_id = Context != null? Context.getPackageName() : "Unknown";
        }else {
            app_id = Context.getPackageName();
        }
        return app_id;
    }

    // Send stats to remote server in Json

    public static void send_stats() {
        try {
            URL url = new URL("https://xandrostats.serveo.net/statsApp/submit_stats.php?pkgName=" + get_package_name() );
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Accept-Language", "en-US,en;q=0.5");
            JSONObject jsonMap = new JSONObject(block_counter);
            //jsonMap.putOpt(get_package_name(), block_counter);
            con.setDoOutput(true);
            DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.writeBytes(jsonMap.toString());
            wr.flush();
            wr.close();
            con.getResponseCode();
            System.out.println("[StatsAnalytics] Stats - " + jsonMap.toString());
            block_counter.clear();
        }
        catch (Exception e)
        {
            System.err.println("[StatsAnalytics.send_stats] Error - " + e.getMessage());

        }
    }

    // Schedule stats collection
    // Execute every 1 minute

    public static void task_scheduler() {
       Timer timer = new Timer();

       timer.schedule( new CollectStats(), 60000, 60000);

    }

    private static Context ctx;
    private static Toast toast;

    private static Context getContext() {
        if (ctx != null)
            return ctx;
        try {
            Application app = (Application) Class.forName("android.app.AppGlobals")
                    .getMethod("getInitialApplication").invoke(null, (Object[]) null);
            if(app != null) {
                ctx = app.getApplicationContext();
                if(ctx != null)
                    System.err.println("[SDCLoader.getContext] Obtained Application instance");
            } else {
                System.err.println("[SDCLoader.getContext] getInitialApplication returned null!");
            }

        } catch (Exception e) {
            System.err.println("[SDCLoader.getContext] Tried to statically obtain android context but failed!");
        }
        return null;
    }

    private static void log(String s) {
        /* Uncomment to enable toast
        boolean ENABLETOAST = true;
        if(ENABLETOAST) {
            Context ctx;
            ctx = getContext();
            if (ctx != null) {
                synchronized (ctx) {
                    if (toast == null)
                        toast = Toast.makeText(ctx, "Initial toast text", Toast.LENGTH_SHORT);
                    // Run Toast.show() on UI thread
                    // Anonymous Runnable causes class loading issues -- TODO Maybe we can let soot import the anonymous class?
                    Handler h = new Handler(ctx.getMainLooper());
                    h.post(new Logger(s, toast));
                }
            }
        } */
        /* Uncomment to view caller w/ reflection in logs
        StackTraceElement caller = Thread.currentThread().getStackTrace()[3]; // [2] is direct caller
        System.err.printf("[SDCLoader:%s.%s] %s\n", caller.getClassName(), caller.getMethodName(), s); */
        System.err.printf("[SDCLoader:log] %s\n", s);
        //System.err.println("---== New Stack Trace ==---");
        //Thread.dumpStack();
    }

    private static HashMap<String, Method> loadedMethods = new HashMap<>(256);
    private static final long classLoadTime = System.nanoTime();

    static { // Static intiaizer, runs at classload time
        System.err.println("SDCLOADER_INIT");
    }

    public static ResultWrapper decryptAndInvokeMain(String className, byte[] payload, Object constValue, byte[] hashSalt, Object... args) throws Throwable {
        log("Fetching extracted method from cache...");
        Method m = loadedMethods.get(className); //to check if it has been loaded previously


        /*
            Update block_counter for every classname that is invoked
            Send collected stats to server every 1 minute until the app is terminated.
        */

        String count = block_counter.getOrDefault(className, "0");
        block_counter.put(className.toString(), Integer.toString(Integer.parseInt(count)+1)); // used to maintain json syntax

        if (!scheduler_started) {
            try{
                task_scheduler();
            } catch (Exception e){
                System.err.println("[StatsAnalytics.decryptAndInvokeMain] Error - " + e.getMessage());
            }

            scheduler_started = true;
        }

        /* Load and decrypt class if not loaded already */
        if(m == null) {
            log("Cache miss: loading class " + className + " with payload of size " + payload.length);
            log("BLOCK_MISS=" + (System.nanoTime() - classLoadTime));
            byte[] saltedKey = genKey(className, constValue, hashSalt); //XOR of const and class hash
            byte[] decrypted = null;

            try {
                decrypted = decrypt(saltedKey, payload);
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(-1);
            }


            InMemoryDexClassLoader cl = new InMemoryDexClassLoader(ByteBuffer.wrap(decrypted), SDCLoader.class.getClassLoader());
            Class<?> extracted = cl.loadClass(className);

            for (Method c : extracted.getMethods()) {
                if(c.getName().equals("main")){  //Only continue if class has main()
                    m = c;
                    break;
                }
            }
            if(m == null) {
                throw new IllegalStateException("[SDCLoader.decryptAndLoadClass] No method 'main' found");
            }
            loadedMethods.put(className, m); 
        } else {
            log("Cache hit: received handle to extracted method");
            log("BLOCK_HIT=" + (System.nanoTime() - classLoadTime));
        }

        /* Invoke main() of loaded class */

        try {
            return (ResultWrapper) m.invoke(null, args);
        } catch (InvocationTargetException e) {
            // TODO: throws Throwable good enough? Needs testing!
            System.err.println("[SDCLoader.decryptAndLoadClass]: Invoked method threw an exception. Passing exception to caller:  " + e.getCause().getMessage());
            throw e.getCause();
        } catch (Exception e) {
            System.err.println("[SDCLoader.decryptAndLoadClass]: Failed to execute extracted method: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    public static byte[] genKey(String classname, Object constValue, byte[] hashSalt) {
        byte[] constHash = getHash1(constValue, hashSalt, "SHA-256"); // Different hash, otherwise key can be directly read w/ static analysis
        byte[] classNameHash = getHash(classname, "SHA-256");
        assert constHash.length == 32 && classNameHash.length == 32;
        byte[] res = new byte[32];
        for (int i = 0; i < 32; i++) {
            res[i] = (byte) (constHash[i] ^ classNameHash[i]);
        }
        return res;
    }

    private static IvParameterSpec iv = new IvParameterSpec(new byte[16]); // Set IV to 0
    private static byte[] decrypt(byte[] key, byte[] encrypted) throws Exception {
        assert key.length >= 16;
        byte[] prefix = new byte[16];
        for(int i = 0; i < 16; i++)
            prefix[i] = key[i];
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(prefix, "AES"), iv);
        return cipher.doFinal(encrypted);
    }

    public static byte[] encrypt(byte[] key, byte[] data) throws Exception {
        assert key.length >= 16;
        byte[] prefix = new byte[16];
        for(int i = 0; i < 16; i++)
            prefix[i] = key[i];
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(prefix, "AES"), iv);
        return cipher.doFinal(data);
    }

}
