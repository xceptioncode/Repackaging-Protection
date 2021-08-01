package ch.ethz.rajs;

import soot.*;
import soot.jimple.*;
import soot.options.Options;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.nio.file.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

import static ch.ethz.rajs.Main.export;

public class NativeUtils {
    public static String CLASS_NAME = "embedded.native";
    public static final String SHARED_OBJECT_NAME = "native-lib";
    public static final String NATIVE_SRC_VENDOR_CPP = "./native/src/vendor.cpp";
    public static final String NATIVE_SRC_VENDOR_H = "./native/src/vendor.h";
    public static final String POST_ENCRYPTED_NATIVE_SECTION_SUFFIX = "_POSTENC";
    private static PrintWriter vendorCpp;
    private static ConcurrentHashMap<SootMethod, Pair<StringBuilder, String>> codegenMap = new ConcurrentHashMap<>();
    public static String nativeCheckName = "#include \"check.h\"\n";
    private static Random rand;
    private static byte[] random_key;
    private static Map<String, String> keyID = new LinkedHashMap<String, String>();


    static {
        if (export)
        {
            CLASS_NAME = "embeddedx.native";
            nativeCheckName = "#include \"checkx.h\"\n";

        }
        try {
            vendorCpp = new PrintWriter(new FileWriter(NATIVE_SRC_VENDOR_CPP));
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(-1);
        }

        vendorCpp.println("#include <jni.h>\n" +
                "#include <android/log.h>\n" +
                "#include <stdlib.h>\n" +
                "#include <stdio.h>\n" +
                "#include <unistd.h>\n" +
                "#include <string.h>\n" +
                "#include <sys/mman.h>\n" +
                "#include <zip.h>\n" +
                "#include <zipint.h>\n" +
                "#include <errno.h>\n" +
                //"#include \"check.h\"\n" +
                nativeCheckName +
                "#define printf(...) __android_log_print(ANDROID_LOG_DEBUG, \"NATIVE\", __VA_ARGS__);\n");
    }

    /**
     * Adds a new class to the Soot scene where all native methods will be declared.
     * Its class initializer dynamically loads the needed shared libraries with {@link java.lang.System#loadLibrary(String)}
     */
    public static void addNativeClass() {
        SootClass nativeClass = new SootClass(CLASS_NAME);
        nativeClass.setSuperclass(Scene.v().getObjectType().getSootClass());
        nativeClass.setModifiers(Modifier.PUBLIC);

        SootMethod classInitializer = new SootMethod("<clinit>", Collections.emptyList(), VoidType.v(), Modifier.STATIC);
        nativeClass.addMethod(classInitializer);

        Body classInitializerBody = Jimple.v().newBody(classInitializer);
        classInitializer.setActiveBody(classInitializerBody);
        classInitializerBody.getUnits().add(Jimple.v().newInvokeStmt(
                Jimple.v().newStaticInvokeExpr(
                        Scene.v().getMethod("<java.lang.System: void loadLibrary(java.lang.String)>").makeRef(),
                        StringConstant.v(SHARED_OBJECT_NAME))
        ));
        classInitializerBody.getUnits().addLast(Jimple.v().newReturnVoidStmt());

        Scene.v().addClass(nativeClass);
        nativeClass.setApplicationClass();
    }

    private static String getNativeJavaMethodName(SootClass SDCClass) {
        return SDCClass.getName().replaceAll("[\\W]|_", "");
    }

    private static String getJNIMethodName(String nativeJavaMethodName) {
        return "Java_" + CLASS_NAME.replaceAll("\\.", "_") + "_" + nativeJavaMethodName;
    }

    private static String getJNIMethodName(SootClass SDCClass) {
        return getJNIMethodName(getNativeJavaMethodName(SDCClass));
    }

    private static String getJNIMethodCallName(Type returnType, boolean isStatic) {
        String returnTypeStr;
        if(returnType == VoidType.v()) {
            returnTypeStr = "Void";
        } else if (returnType instanceof PrimType) {
            returnTypeStr = returnType.toString();
            // Capitalize first character
            returnTypeStr = returnTypeStr.substring(0, 1).toUpperCase() + returnTypeStr.substring(1);
        } else {
            returnTypeStr = "Object";
        }
        return String.format("Call%s%sMethod", isStatic ? "Static" : "", returnTypeStr);
    }

    /**
     * Converts Soot type to a JNI type used in C/C++ code
     * Reference: https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/types.html
     * @param type  Soot type
     * @return      JNI type
     */
    private static String getJNIType(Type type) {
        if(type == VoidType.v()) return "void";
        if(type instanceof PrimType) {
            String JNIType = "j" + type.toString();
            assert Arrays.stream(new String[] {"jboolean", "jbyte", "jchar", "jshort", "jint", "jlong", "jfloat", "jdouble"}).anyMatch(JNIType::equals);
            return JNIType;
        }
        return "jobject";
    }

    /**
     * Generates checking and decryption code to be compiled to the shared object
     * This method also substitutes an invocation expression to one that is instead woven into the encrypted checking code
     * Method signature of replaced method expression: nativeMethod(key, [object], [original args])
     *
     * @param SDCClass  SDC class in which we invoke the native check method
     * @param key       Key used to encrypt code weaving part
     * @param keyLocal  Local byte[] containing key
     */
    public static synchronized void addCheckRoutine(SootClass SDCClass, byte[] key, Local keyLocal) {
        SootClass nativeClass = Scene.v().getSootClass(CLASS_NAME);

        String JNIMethodName = getJNIMethodName(SDCClass);

        List<Pair<String, String>> JNIArguments = new ArrayList<>(); // List of (type, name) pairs of the JNI method signature
        JNIArguments.add(new Pair<>("JNIEnv *", "env")); // JNI pointer
        JNIArguments.add(new Pair<>("jclass", "SDC_class")); // Class that called the native method (in the case of a static native method invocation)
        JNIArguments.add(new Pair<>("jbyteArray", "jni_decryption_key")); // Decryption key of checking code

        List<Type> nativeMethodArgTypes = new ArrayList<>();
        nativeMethodArgTypes.add(ArrayType.v(ByteType.v(), 1)); // key

        SootMethod SDCMethod = SDCClass.getMethods().stream().filter(m -> m.getName().equals("main"))
                .findFirst().orElseThrow(() ->
                        new IllegalStateException("SDCClass does not contain main(...)!"));
        String JNICodeWeaveBody = "";
        SootMethod nativeMethod = null;
        Type returnType = null;
        /* Code weave a method call expression */
        boolean foundCandidate = false;
        if(Main.nativeCodeWeavingEnabled()) {
            ValueBox invokeExprBox = null;
            InvokeExpr origInvokeExpr = null;
            for (Iterator it = SDCMethod.getActiveBody().getUnits().snapshotIterator(); it.hasNext(); ) {
                Stmt u = (Stmt) it.next();
                if (!u.containsInvokeExpr()) continue;
                invokeExprBox = u.getInvokeExprBox();
                origInvokeExpr = (InvokeExpr) invokeExprBox.getValue();
                if(origInvokeExpr.getMethod().getDeclaringClass().equals(SDCClass)) continue; // Skip calls to main() of SDCClass, since class name contains illegal characters (dashes) for JNI calls ;)
                // Don't pass uninitialized reference to JNI native method
                // We get a VerifyError otherwise:
                // register has type Uninitialized Reference but expected Reference
                // An alternative is to initialize the variable to a null reference, but we chose to ignore constructors
                if(origInvokeExpr.getMethod().isConstructor()) continue;
                foundCandidate = true;
                break;
            }

            if(foundCandidate) {
                returnType = origInvokeExpr.getMethod().getReturnType();

                if(origInvokeExpr instanceof InstanceInvokeExpr) {
                    // Pass instance for non-static method invocations
                    Value receiver = ((InstanceInvokeExpr) origInvokeExpr).getBase();
                    nativeMethodArgTypes.add(receiver.getType());
                    JNIArguments.add(new Pair<>(getJNIType(receiver.getType()), "receiver"));
                }

                // Pass arguments from original method call expression to native method
                nativeMethodArgTypes.addAll(origInvokeExpr.getMethod().getParameterTypes());
                int argId = 0;
                for (Type t : origInvokeExpr.getMethod().getParameterTypes()) {
                    JNIArguments.add(new Pair<>(getJNIType(t), "a" + (argId++)));
                }

                // Get JVM type signature to look up method id in native code. It is of form (argument-types)return-type
                String JVMTargetMethodTypeSignature = AbstractJasminClass.jasminDescriptorOf(origInvokeExpr.getMethodRef());
                List<String> passedArgs = new ArrayList<>(); // a1, a2, ...
                if(origInvokeExpr instanceof InstanceInvokeExpr) {
                    passedArgs.add("receiver");
                } else {
                    passedArgs.add("cls");
                }
                passedArgs.add("mid");
                for(int i = 0; i < argId; i++) {
                    passedArgs.add("a" + i);
                }
                // Set C/C++ params
                // Note that we call functions of the JNI struct à la C instead of C++, since we don't want to generate
                // weak symbols in-between the encrypted method and the native method called by the Java runtime
                if(origInvokeExpr instanceof StaticInvokeExpr) {
                    String JVMTargetClassName = AbstractJasminClass.slashify(origInvokeExpr.getMethod().getDeclaringClass().getName());
                    JNICodeWeaveBody += "cls = env->functions->FindClass(env, \"" + JVMTargetClassName + "\");\n" +
                            "if(cls == NULL) { printf(\"No class found!\\n\"); }\n" +
                            String.format("mid = env->functions->GetStaticMethodID(env, cls, \"%s\", \"%s\");\n", origInvokeExpr.getMethod().getName(), JVMTargetMethodTypeSignature) +
                            "if (mid == 0) { printf(\"No method id found!\\n\"); }\n" +
                            String.format("return env->functions->%s(env, %s);\n", getJNIMethodCallName(returnType, true),
                                    String.join(", ", passedArgs)
                            );
                } else if(origInvokeExpr instanceof InstanceInvokeExpr) {
                    JNICodeWeaveBody += "cls = env->functions->GetObjectClass(env, receiver);\n" +
                            "if(cls == NULL) { printf(\"No class found!\\n\"); }\n" +
                            String.format("mid = env->functions->GetMethodID(env, cls, \"%s\", \"%s\");\n", origInvokeExpr.getMethod().getName(), JVMTargetMethodTypeSignature) +
                            "if (mid == 0) { printf(\"No method id found!\\n\"); }\n" +
                            String.format("return env->functions->%s(env, %s);\n", getJNIMethodCallName(returnType, false),
                                    String.join(", ", passedArgs)
                            );
                } else {
                    System.err.println("Ignoring unknown invoke expression");
                }

                /* Add JNI method to CLASS_NAME */
                nativeMethod = new SootMethod(getNativeJavaMethodName(SDCClass), nativeMethodArgTypes, returnType, Modifier.PUBLIC | Modifier.STATIC | Modifier.SYNCHRONIZED | Modifier.NATIVE);
                nativeClass.addMethod(nativeMethod);

                /* Redirect method call to our native code */
                List<Value> nativeMethodArgs = new ArrayList<>();
                nativeMethodArgs.add(keyLocal);
                if(origInvokeExpr instanceof InstanceInvokeExpr) {
                    nativeMethodArgs.add(((InstanceInvokeExpr) origInvokeExpr).getBase());
                }
                nativeMethodArgs.addAll(origInvokeExpr.getArgs());
                invokeExprBox.setValue(Jimple.v().newStaticInvokeExpr(nativeMethod.makeRef(), nativeMethodArgs));
            }

        }

        if(!foundCandidate) {
            returnType = VoidType.v();

            /* Add JNI method to CLASS_NAME */
            nativeMethod = new SootMethod(getNativeJavaMethodName(SDCClass), nativeMethodArgTypes, returnType, Modifier.PUBLIC | Modifier.STATIC | Modifier.SYNCHRONIZED | Modifier.NATIVE);
            nativeClass.addMethod(nativeMethod);

            /* Insert check at beginning of SDC block. Pass key to JNI */
            Unit keyInit = null;
            for (Iterator it = SDCMethod.getActiveBody().getUnits().snapshotIterator(); it.hasNext(); ) {
                keyInit = (Unit) it.next();
                if (keyInit instanceof AssignStmt && ((AssignStmt) keyInit).getLeftOp() == keyLocal && ((AssignStmt) keyInit).getRightOp() instanceof NewArrayExpr) {
                    // Skip until we reach keyLocal[15] = ...;
                    for(int i = 0; i < key.length; i++)
                        keyInit = (Unit) it.next();
                    assert keyInit instanceof AssignStmt && ((AssignStmt) keyInit).getLeftOp() instanceof ArrayRef;
                    break;
                }
            }
            assert keyInit != null;
            SDCMethod.getActiveBody().getUnits().insertAfter(
                    Jimple.v().newInvokeStmt(Jimple.v().newStaticInvokeExpr(nativeMethod.makeRef(), keyLocal))
                    , keyInit
            );
        }

        rand = new Random();
        random_key = new byte[16];
        rand.nextBytes(random_key);
        //String encryptedMethodName = JNIMethodName + "_" + javax.xml.bind.DatatypeConverter.printHexBinary(random_key); // + "_KEY_" + javax.xml.bind.DatatypeConverter.printHexBinary(key);
        String encryptedMethodName = JNIMethodName + "_nameID_" + javax.xml.bind.DatatypeConverter.printHexBinary(random_key);

        keyID.put(javax.xml.bind.DatatypeConverter.printHexBinary(random_key), javax.xml.bind.DatatypeConverter.printHexBinary(key));

        /* Add C++ method signature to a StringBuilder */
        assert !codegenMap.containsKey(nativeMethod);
        StringBuilder codegen = new StringBuilder();
        codegenMap.put(nativeMethod, new Pair<>(codegen, JNICodeWeaveBody));
        codegen.append(
                String.format("extern \"C\" %s %s(%s) {\n", getJNIType(returnType),
                        encryptedMethodName, String.join(", ", JNIArguments.stream().map(p -> p.getLeft() + " " + p.getRight()).collect(Collectors.toList()))) +
                        //   "    printf(\"Entered segment\");\n"  +
                        "    jclass cls;\n" +
                        "    jmethodID mid;\n" //+
        );
        if (!export) {
            codegen.append("    printf(\"Hello decrypted world!\");\n");
        }
        codegen.append(
                "    TEMPLATE \n" +
                        "}\n\n" +
                        String.format("extern \"C\" JNIEXPORT %s JNICALL %s(%s) {\n", getJNIType(returnType),
                                JNIMethodName, String.join(", ", JNIArguments.stream().map(p -> p.getLeft() + " " + p.getRight()).collect(Collectors.toList()))) //+
        );
        if (!export){
            codegen.append("    printf(\"Invoked from " + JNIMethodName + "\");\n");
        }
        codegen.append(
                "    int fptr_correction = 0; \n" +
                        "    static bool decrypted = false;\n" +
                        "    size_t code_len = (size_t) (((char *)&" + JNIMethodName + ") - ((char *)&" + encryptedMethodName + "));\n" +
                        "    jbyte *key = NULL;\n" +
                        "    if(decrypted) { \n" //+
        );
        if (!export) {
            codegen.append("    printf(\"Code already decrypted. Jumping to decrypted code!\\n\");\n");
        }
        codegen.append(
                "        goto CHK_START; \n" +
                        "    }\n" //+
        );
        if (!export) {
            codegen.append("    printf(\"chk start: %p\\nlen: %zd\",(void *) &" + encryptedMethodName + ", code_len);\n"); //+
        }
        codegen.append(
                "    key = env->functions->GetByteArrayElements(env, jni_decryption_key, NULL);\n" +
                        "    if(key == NULL) { printf(\"Failed to obtain key byte array from JNI\"); }\n" +
                        // The function pointer obtained at runtime for armeabi-v7a differs by a 1 byte offset compared
                        // to the statically determined file offset in the symbol table
                        "#ifdef __thumb__\n" +
                        "    fptr_correction = -1; \n" +
                        "#endif\n"+
                        //+ fptr_correction after parenthesis

                        "    if(decrypt_code(((char *) &" + encryptedMethodName + "), code_len, (unsigned char *)key) == 0) {\n" //+
        );
        if (!export) {
            codegen.append("      printf(\"DECRYPT: Success\");\n");
        }
        codegen.append(
                "    } else {\n" +
                        "      printf(\"DECRYPT: FAIL\");\n" +
                        "    }\n" +


                        "    env->functions->ReleaseByteArrayElements(env, jni_decryption_key, key, JNI_ABORT);\n" +
                        "    decrypted = true;\n" //+
        );
        if (!export) {
            codegen.append("    printf(\"Entering decrypted segment...\");\n");
        }
        codegen.append(                "    CHK_START:\n" +
                String.format("    return %s(%s);\n", encryptedMethodName, String.join(", ", JNIArguments.stream().map(Pair::getRight).collect(Collectors.toList()))) +
                "}\n\n"
        );

        assert nativeClass.getMethods().contains(nativeMethod); // Sometimes we get a No static method ... when synchronized wasn't present. TODO: Test if we need to sync. method collection
    }

    public static void installNativeLibs() throws IOException, InterruptedException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if (Options.v().process_dir().size() != 1) {
            throw new IllegalArgumentException("Not a single APK was provided");
        }

        Path sourceAPKPath = ManifestEditor.getAPKOutputPath(); // Transformed APK path before injecting native libs

        /* Write package name to native code source files to check package name */
        String packageName = ManifestEditor.getPackageName();
        PrintWriter vendorH = new PrintWriter(new FileWriter(NATIVE_SRC_VENDOR_H));
        vendorH.printf("#define APK_PACKAGE_NAME \"%s\"\n", packageName);
        vendorH.close();

        // Obtain paths of dex files
        FileSystem zipFS = FileSystems.newFileSystem(sourceAPKPath, null);
        final PathMatcher toCheckMatcher = zipFS.getPathMatcher("glob:**{.dex,AndroidManifest.xml}"); // We can change it to check other files as well such as res
        Set<Path> toCheckPaths = new HashSet<>();
        for (Path root : zipFS.getRootDirectories()) {
            Files.walk(root).filter(toCheckMatcher::matches).forEach(toCheckPaths::add);
        }

        assert toCheckPaths.stream().anyMatch(path -> path.getFileName().toString().equals("classes.dex"));

        for (SootMethod nativeMethod : codegenMap.keySet()) {
            Pair<StringBuilder, String> codegenWeavePair = codegenMap.get(nativeMethod);
            StringBuilder codegen = codegenWeavePair.getLeft();
            Path toCheckPath;
            // Obtain random file to check
            {
                int size = toCheckPaths.size();
                int idx = ThreadLocalRandom.current().nextInt(size);
                Iterator<Path> iterator = toCheckPaths.iterator();
                do {
                    assert iterator.hasNext();
                    toCheckPath = iterator.next();
                    idx--;
                } while (idx >= 0);
            }
            long size = Files.size(toCheckPath);
            long offset = ThreadLocalRandom.current().nextLong(size); //0;
            long count = ThreadLocalRandom.current().nextLong(size - offset); // Long.min(100, size - offset); //
            int hash = xorFile(toCheckPath, (int) count, (int) offset);

            /* Add hash assertions to native code */

            /* Write generated code to cpp file */
            if (export) {
                vendorCpp.write(codegen.toString().replace("TEMPLATE", "    static bool didCheck;\n" +
                        "    static bool pass;\n" +
                        //   "      printf(\"Before did check.\");\n" +
                        "    if(!didCheck) {\n" +
                        //   "    printf(\"Entered did check.\");\n" +
                        "       const char *file_name = \"" + toCheckPath.getFileName().toString() + "\"; \n " +
                        "       size_t count = " + count + "; \n" +
                        "       size_t offset = " + offset + "; \n " +
                        "       int err = 0; \n" +
                        "       const char *apk_path = get_apk_path(); \n" +
                        // Open APK
                        "       zip *z = zip_open(apk_path, 0, &err); \n" +
                        "       if(err) { \n " +
                        "           __builtin_trap(); \n" +
                        //"           printf(\"Failed to open apk: %i\", err); \n" +
                        "           //return 0; \n" +
                        "       }\n" +

                        // Stat file inside APK archive
                        "       struct zip_stat st; \n" +
                        "       zip_stat_init(&st); \n" +
                        "       zip_stat(z, file_name, 0, &st); \n" +

                        //"       printf(\"Found %s in %s of size %li\", file_name, apk_path, st.size); \n " +
                        "       if(offset + count > st.size) { \n " +
                        "           __builtin_trap(); \n" +
                        //"           printf(\"Requested hash of file range that is out of bounds\"); \n" +
                        "       //return 0;\n"+
                        "       }\n"+

                        "       char *uncompressed = new char[offset+count]; \n" +

                        "       zip_file *f; \n" +
                        "       if ((f = zip_fopen(z, file_name, 0)) == NULL) { \n" +
                        "           __builtin_trap(); \n" +
                        //"           printf(\"Could not open file in archive: %i\", z->error); \n" +
                        "           //return 0; \n" +
                        "       } \n" +

                        "       ssize_t read = zip_fread(f, uncompressed, offset + count); \n" +
                        "       if(read < 0) { \n" +
                        "           __builtin_trap(); \n" +
                        //"           printf(\"Failed to read file in archive\"); \n" +

                        "           //return 0; \n" +
                        "       } \n" +
                        //"       printf(\"Read %zi bytes\", read); \n" +
                        "       zip_fclose(f); \n" +
                        "       zip_close(z); \n" +

                        "       const char *arr = uncompressed+offset; \n" +

                        "       char hash[4]; \n" +
                        "       memset(hash, 0, sizeof(hash)); \n" +
                        "       for(size_t read = 0; read < count; read++) {\n" +
                        "           hash[read % 4] ^= arr[read]; \n" +
                        "       } \n" +

                        "       int32_t hash1 = hash[0] + (hash[1] << 8) + (hash[2] << 16) + (hash[3] << 24); \n" +
                        "       //printf(\"Hash Calculated %zu\", hash1); \n " +
                        "       delete[] uncompressed; \n" +
                        "       pass = " + hash + " == hash1; \n" +
                        //"        pass = " + hash + " == hash_file_in_apk(\"" + toCheckPath.getFileName().toString() +
                        //"\", " + count + ", " + offset + ");\n" +
                       // "        anti_debug(); \n" + // This needs the APK to have debuggable=true in androidManifest
                        "        anti_debug_traceid(); \n" +
                        "        didCheck = true;\n" +
                        "    }\n" +

                        "    if (pass) {\n" +
                        "       // printf(\"PASS!\\n\");\n" + codegenWeavePair.getRight() + "\n" +
                        "    } else {\n" +
                        " // Raise SigFault - Crash \n" +
                        "         *((int *)0) = 0; /* printf(\"Hash check failed!\\n\"); */\n" +
                        "        __builtin_trap(); \n" +
                        "    }\n"));
            } else {
                vendorCpp.write(codegen.toString().replace("TEMPLATE", "    static bool didCheck;\n" +
                        "    static bool pass;\n" +
                        //   "      printf(\"Before did check.\");\n" +
                        "    if(!didCheck) {\n" +
                        //   "    printf(\"Entered did check.\");\n" +
                        "       const char *file_name = \"" + toCheckPath.getFileName().toString() + "\"; \n " +
                        "       size_t count = " + count + "; \n" +
                        "       size_t offset = " + offset + "; \n " +
                        "       int err = 0; \n" +
	                    "       const char *apk_path = get_apk_path(); \n" +
                // Open APK
                        "       zip *z = zip_open(apk_path, 0, &err); \n" +
                        "       if(err) { \n " +
                        "           printf(\"Failed to open apk: %i\", err); \n" +
                        //"           //return 0; \n" +
                        "       }\n" +

                // Stat file inside APK archive
                        "       struct zip_stat st; \n" +
                        "       zip_stat_init(&st); \n" +
                        "       zip_stat(z, file_name, 0, &st); \n" +

                        "       printf(\"Found %s in %s of size %li\", file_name, apk_path, st.size); \n " +
                        "       if(offset + count > st.size) { \n " +
                        "           printf(\"Requested hash of file range that is out of bounds\"); \n" +
                        //"       //return 0;\n"+
                        "       }\n"+

                        "       char *uncompressed = new char[offset+count]; \n" +

                        "       zip_file *f; \n" +
                        "       if ((f = zip_fopen(z, file_name, 0)) == NULL) { \n" +
                        "           printf(\"Could not open file in archive: %i\", z->error); \n" +
                        //"           //return 0; \n" +
                        "       } \n" +

                        "       ssize_t read = zip_fread(f, uncompressed, offset + count); \n" +
                        "       if(read < 0) { \n" +
                        "           printf(\"Failed to read file in archive\"); \n" +
                        //"           //return 0; \n" +
                        "       } \n" +
                        "       printf(\"Read %zi bytes\", read); \n" +
                        "       zip_fclose(f); \n" +
                        "       zip_close(z); \n" +

	                    "       const char *arr = uncompressed+offset; \n" +

                        "       char hash[4]; \n" +
                        "       memset(hash, 0, sizeof(hash)); \n" +
                        "       for(size_t read = 0; read < count; read++) {\n" +
                        "           hash[read % 4] ^= arr[read]; \n" +
                        "       } \n" +

                        "       int32_t hash1 = hash[0] + (hash[1] << 8) + (hash[2] << 16) + (hash[3] << 24); \n" +
                        "       //printf(\"Hash Calculated %zu\", hash1); \n " +
                        "       delete[] uncompressed; \n" +
                        "       pass = " + hash + " == hash1; \n" +
                        "       anti_debug(); \n" +
                        "       didCheck = true;\n" +
                        "    }\n" +

                        "    if (pass) {\n" +
                        "        printf(\"PASS!\\n\");\n" + codegenWeavePair.getRight() + "\n" +
                        "    } else {\n" +
                        "        printf(\"Hash check failed!\\n\");\n" +
                        "    }\n" +
                        "    printf(\"Integrity check complete.\");"));
            }

        }
        vendorCpp.flush();

        /* Compile the native library */
        List<String> command = new ArrayList<>();
        if (export) {
            command.add("./cmakex/native-build"); // Build script for export version with different CMakeList
            command.add("./cmakex"); // src-dir
        } else {
            command.add("./native-build"); // Build script
            command.add("."); // src-dir
        }
        command.add("./out/lib"); // out-dir
        command.addAll(ManifestEditor.getCompatibleArchitectures());
        ProcessBuilder pb = new ProcessBuilder(command.toArray(new String[0]))
                .directory(new File("native")) // To find default.nix
                .inheritIO(); // Redirect output to current process
        Process p = pb.start();
        if (p.waitFor() != 0) {
            throw new CompilationDeathException("Failed to compile native libraries!");
        }

        /* Encrypt marked sections */


        for (Path libPath : Files.walk(Paths.get("native/out/"))
                .filter(Files::isRegularFile).collect(Collectors.toList())) {
            System.out.println("Encrypting sections of file " + libPath.toString());
            //Files.copy(libPath, libPath.resolveSibling(libPath.getFileName().toString() + ".decrypted"));
            RandomAccessFile libFile = new RandomAccessFile(new File(libPath.toString()), "rw");
            pb = new ProcessBuilder("nm", "--numeric-sort", "--defined-only", libPath.toAbsolutePath().toString());
            p = pb.start();
            BufferedReader reader =
                    new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder builder = new StringBuilder();
            String encSymbolLine;
            int processedSections = 0;
            while ((encSymbolLine = reader.readLine()) != null) {
                Symbol sym = new Symbol(encSymbolLine);
                if (!sym.name.startsWith("Java_") || !sym.name.contains("_nameID_") || sym.name.startsWith("_"))
                    continue;
                //System.out.println("NAMEID: " + Arrays.stream(sym.name.split("_")).reduce((f, s) -> s).get());
                String hexKey = keyID.get(Arrays.stream(sym.name.split("_")).reduce((f, s) -> s).get());
                //System.out.println("KEY : " + hexKey);
                int offset = sym.offset;
                byte[] key = DatatypeConverter.parseHexBinary(hexKey);
                assert key.length == 16;
                byte[] iv = new byte[16]; // iv set to all 0s
                Symbol postSym = new Symbol(reader.readLine());
                while (!postSym.type.equals("T")) {
                    System.out.println("[WARN] Ignoring symbol that is not a global symbol in the text field: " + postSym.toString());
                    postSym = new Symbol(reader.readLine());
                }
                System.out.println("Found end of encrypted function " + sym.name + " at symbol " + postSym.toString());
                // Ensure that no method in between is encrypted
                assert postSym.name.contains("Java_") && !postSym.name.contains("_nameID_");
                //assert postEncSymbolLine.endsWith(POST_ENCRYPTED_NATIVE_SECTION_SUFFIX);
                int len = postSym.offset - offset;
                assert len >= 0;
                System.out.printf("Encrypting native code for symbol %s of length %d\n", sym.name, len);
                // Encrypt instructions with key provided by exported symbols
                byte[] encIBytes;
                {
                    byte[] iBytes = new byte[len];
                    libFile.seek(offset);
                    libFile.read(iBytes);
//                    System.out.println("UNENCRYPTEDBYTES: " + iBytes.toString());
//                    String salt_string ="";

//                    for (int i = 0; i < iBytes.length; i++) {
//                        salt_string += Integer.toHexString((0x000000ff & iBytes[i]) | 0xffffff00).substring(6);
//                    }
//                    System.out.println("UNENCRYPTEDSTR: " + salt_string);
                    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
                    IvParameterSpec ivSpec = new IvParameterSpec(iv);
                    Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
                    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
                    encIBytes = cipher.update(iBytes);
                }
                // Write encrypted contents back to file
                libFile.seek(offset);
                libFile.write(encIBytes);
                processedSections++;
            }
            libFile.close();
            assert processedSections == codegenMap.size();

            if (export) { // Strip all non-global symbols so we do not have unnecessary symbols, make debugging harder, and further reduce the lib size
                System.out.println("Stripping symbols from " + libPath);
                pb = new ProcessBuilder("aarch64-linux-gnu-strip", "--strip-all", "--discard-all", libPath.toAbsolutePath().toString())
                        .inheritIO(); // Redirect output to current process
                p = pb.start();
                if (p.waitFor() != 0) {
                    //throw new CompilationDeathException("Failed to strip native library!");
                    // Format Error detected - try with default program
                    pb = new ProcessBuilder("strip", "--strip-all", "--discard-all", libPath.toAbsolutePath().toString())
                            .inheritIO(); // Redirect output to current process
                    p = pb.start();
                    if (p.waitFor() != 0) {
                        throw new CompilationDeathException("Failed to strip native library!");
                    }
                }
            }
        }

        /* Copy the compiled lib folder to the target APK */
        Path compiledLibsPath = Paths.get("native/out/");
        File newTempApk = File.createTempFile("new-apk", ".apk");
        FileOutputStream targetApkOutputStream = new FileOutputStream(newTempApk.getAbsolutePath());
        //DexUtils.mergePathWithAPK(new ZipFile(sourceAPKPath.toString()), compiledLibsPath, new ZipOutputStream(targetApkOutputStream));
        DexUtils.mergePathWithAPK(new ZipFile(sourceAPKPath.toString()), new ZipFile(ManifestEditor.getAPKInputPath().toString()), compiledLibsPath, new ZipOutputStream(targetApkOutputStream));

        //FileOutputStream targetApkOutputStream1 = new FileOutputStream(newTempApk.getAbsolutePath());
        //DexUtils.mergePathWithAPK1(new ZipFile(ManifestEditor.getAPKInputPath().toString()), new ZipOutputStream(targetApkOutputStream1));

        /* Replace transformed APK with the newly created apk that contains the native libs */
        Files.delete(sourceAPKPath);

        Files.move(newTempApk.toPath(), sourceAPKPath);
    }

    // Corresponds to same computation in native code
    private static int xorFile(Path p, int count, int offset) throws IOException {
        byte[] contents = Files.readAllBytes(p);
        byte[] res = new byte[4];
        for(int i = offset; i < (offset + count); i++ ) {
            res[(i - offset) % 4] ^= contents[i];
        }
        // 0xff masks required to undo Java's sign extension on bytes
        return (0xff & res[0]) + ((0xff & res[1]) << 8) + ((0xff & res[2]) << 16) + ((0xff & res[3]) << 24);
    }
}

class Symbol {
    public int offset;
    public String type;
    public String name;

    /**
     * Parse output of nm to a symbol instance
     * @param nmLine A line of output provided by nm
     */
    public Symbol(String nmLine) {
        System.out.println("Parsing nm output for line: " + nmLine);
        String[] split = nmLine.trim().split("\\s+");
        if(split.length != 3) {
            if(split.length == 2 && split[1].equals("N")) {
                System.out.println("Ignoring debug symbol");
            } else {
                // Most likely an undefined symbol. The `--defined-only` argument should be set
                assert false;
            }
        }
        offset = Integer.parseInt(split[0], 16);
        type = split[1];
        name = split.length >= 3 ? split[2] : "";
    }

    @Override
    public String toString() {
        return String.format("offset: %d, type: %s, name: %s", offset, type, name);
    }
}
