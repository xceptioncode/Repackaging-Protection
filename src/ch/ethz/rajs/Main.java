package ch.ethz.rajs;

//import org.jboss.util.collection.ConcurrentReferenceHashMap;

import ch.ethz.rajs.transformers.SDCBodyTransformer;
import soot.*;
import soot.options.Options;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;

public class Main {
    public static boolean TEST_TARGET = false;

    public static boolean nativeEnabled() {
        return !TEST_TARGET && true;
    }

    public static boolean nativeCodeWeavingEnabled() {
        return true;
    }

    public static boolean dexEncryptionEnabled() {
        return !TEST_TARGET && true;
    }

    public static boolean transformOnlyIfStatement() { return false; }

    public static boolean architecture_all = false;

    public static boolean replaceWithIf = false;  // Keep it true for running the test or edit the script

    public static boolean experimentalFeatures = false; // Used for Switch and inequality transformation

    public static boolean hotMethodsListFound = false;

    public static String hotMethodsListFileName = "";

    public static int maxSwitchCases = 5; // if total number of cases in a Switch is more than maxSwitchCases, then don't replace by if. - Performance reasons.

    public static Set<String> hotMethodsList = new HashSet<String>();

    public static boolean export = false;

    public static String packageName = "";

    public static boolean calcTime = false;

    public static void main(String[] args) {
        if (args.length == 0) {
            /*
            Options.v().set_force_overwrite(true);
            Options.v().set_process_multiple_dex(true);
            Options.v().set_allow_phantom_refs(true);
            Options.v().set_android_jars("/home/ili/Android/Sdk/platforms");
            args = new String[]{"-process-dir", APK_PATH}; */

            // Test module is marked as a dependency. Running Soot debug configuration will cause classes to build in ./sootOutput/Test
            args = new String[]{"-process-dir", "sootOutput/Test/"};
            Options.v().set_output_dir("./sootOutput/Test");
            Options.v().set_whole_program(true);
        } else {
            //Options.v().parse(args);
        }


        Options.v().parse(args);
        Options.v().set_whole_program(true);

        for (int i=0; i<args.length; i++) {
            //System.out.println(args[i]);

            if (args[i].equals("-arch")) {
                if (args[i + 1].equals("all")) architecture_all = true;
            } else if (args[i].equals("-max")) {
                if (args[i + 1].equals("yes")) replaceWithIf = true;
            } else if (args[i].equals("-exp")) {
                if (args[i + 1].equals("yes")) experimentalFeatures = true;
            } else if (args[i].equals("-export")) {
                if (args[i + 1].equals("yes")) export = true;
            } else if (args[i].equals("-timer")) {
                if (args[i + 1].equals("yes")) calcTime = true;
            } else if (args[i].equals("-hotMethod")) {
                if (args[i + 1].endsWith(".list"))
                {
                    hotMethodsListFileName = args[i+1];
                    hotMethodsListFound = true;
                }

            }
        }

        if (hotMethodsListFound) {
            try {
                Scanner s = new Scanner(new File(hotMethodsListFileName));
                while (s.hasNextLine()) {
                    hotMethodsList.add(s.nextLine());
                }
                s.close();
            } catch (Exception e) {
                throw new RuntimeException("Hot methods file not found, ensure filepath is correct!");
            }
        }

        if (nativeEnabled())
        {
            //packageName = ManifestEditor.getPackageName();
        }

        TEST_TARGET = Options.v().output_format() != Options.output_format_dex;
        if(TEST_TARGET) {
            System.err.println("Running as TEST_TARGET!");
            //replaceWithIf = true;
        }
        //Options.v().set_output_format(Options.output_format_jimple);
        Options.v().set_soot_classpath(
                Scene.v().defaultClassPath() + ":./out/production/Transformer:" +
                        System.getProperty("user.home") + "/Android/Sdk/platforms/android-26/android.jar"
        );

        Scene.v().loadClassAndSupport("java.lang.Object");
        Scene.v().addBasicClass("java.lang.IllegalStateException", SootClass.SIGNATURES);

        if (export) // Export version without Logs
        {
            injectClasses(new String[] {
                    "embeddedx.SDCLoader",
                    "embeddedx.Logger",
                    "embeddedx.ResultWrapper",
            });
        } else {
            injectClasses(new String[]{
                    "embedded.SDCLoader",
                    "embedded.Logger",
                    "embedded.ResultWrapper",
                    "embedded.CollectStats"
            });
        }

        NativeUtils.addNativeClass();

        PackManager.v().getPack("jtp").add(new Transform("jtp.sdc", new SDCBodyTransformer()));
        PackManager.v().runPacks();
        PackManager.v().writeOutput();

        if(nativeEnabled()) {
            /* Set required permissions to launch gdbserver */
            if (!export) {
                ManifestEditor.addPermission("android.permission.INTERNET"); // Not needed if we use stdin/stdout fds for communication with gdb
                ManifestEditor.setDebuggable();
            }
            try {
                NativeUtils.installNativeLibs();
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(-1);
            }
        }
    }

    private static void injectClasses(String[] classes) {
        for (String c: classes)
            Scene.v().addBasicClass(c, SootClass.BODIES);
        Scene.v().loadNecessaryClasses();
        for (String c: classes)
            Scene.v().getSootClass(c).setApplicationClass(); // Mark class to be part of output
    }
}
