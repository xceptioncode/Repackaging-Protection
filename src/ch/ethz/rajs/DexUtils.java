package ch.ethz.rajs;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public class DexUtils {
    public static List<String> copiedFileList = new ArrayList<String>();
    public static void mergePathWithAPK(ZipFile apk, ZipFile inputApk, Path dir, ZipOutputStream destination) throws IOException {
        Enumeration sourceEntries = apk.entries();
        Enumeration originialEntries = inputApk.entries();

        while(sourceEntries.hasMoreElements()) {
            ZipEntry sourceEntry = (ZipEntry)sourceEntries.nextElement();;
            String sourceEntryName = sourceEntry.getName();

            // uncomment to remove armv7 that we don't support.
//            System.out.println(sourceEntryName);
//            if (sourceEntryName.split("/").length >= 2) {
//                if (sourceEntryName.split("/")[1].equals("armeabi-v7a")) continue;
//                if (sourceEntryName.split("/")[1].equals("x86")) continue;
//            }

            copiedFileList.add(sourceEntryName);
            ZipEntry destinationEntry = new ZipEntry(sourceEntryName);
            destinationEntry.setMethod(sourceEntry.getMethod());
            destinationEntry.setSize(sourceEntry.getSize());
            destinationEntry.setCrc(sourceEntry.getCrc());
            destination.putNextEntry(destinationEntry);
            InputStream zipEntryInput = apk.getInputStream(sourceEntry);
            byte[] buffer = new byte[2048];

            for(int bytesRead = zipEntryInput.read(buffer); bytesRead > 0; bytesRead = zipEntryInput.read(buffer)) {
                destination.write(buffer, 0, bytesRead);
            }

            zipEntryInput.close();
        }

        System.out.println("Now comparing with original input file ... ");

        /*
            This is to ensure we have the non-generic dex files (classes1..n.dex) at same location as original file.
            This compares originalAPK input and newly generated input for non generic dex files, if found copy that to new APK
            to fix java.lang.RuntimeException: java.io.FileNotFoundException: (audience_network.dex |  other.dex) error which has been noted at multiple APK.

            Reason: SOOT creates dex files with generic name and location, if APK checks for any specific dex - at particular location, -> lead to error.

         */
        while(originialEntries.hasMoreElements()) {
            ZipEntry sourceEntry = (ZipEntry)originialEntries.nextElement();;
            String sourceEntryName = sourceEntry.getName();

            if (sourceEntryName.endsWith(".dex") && !(sourceEntryName.split("/")[sourceEntryName.split("/").length - 1].startsWith("classes"))) {

                if (!(copiedFileList.contains(sourceEntryName))) {

//                    System.out.println(sourceEntryName);
                    ZipEntry destinationEntry = new ZipEntry(sourceEntryName);
                    destinationEntry.setMethod(sourceEntry.getMethod());
                    destinationEntry.setSize(sourceEntry.getSize());
                    destinationEntry.setCrc(sourceEntry.getCrc());
                    destination.putNextEntry(destinationEntry);
                    InputStream zipEntryInput = inputApk.getInputStream(sourceEntry);
                    byte[] buffer = new byte[2048];

                    for(int bytesRead = zipEntryInput.read(buffer); bytesRead > 0; bytesRead = zipEntryInput.read(buffer)) {
                        destination.write(buffer, 0, bytesRead);
                    }

                    zipEntryInput.close();
                }
            }
            else
                continue;
        }


        Files.walk(dir)
                .filter(path -> !Files.isDirectory(path))
                .forEach(path -> {
                    ZipEntry zipEntry = new ZipEntry(dir.relativize(path).toString());
                    try {
                        destination.putNextEntry(zipEntry);
                        Files.copy(path, destination);
                        destination.closeEntry();
                    } catch (IOException e) {
                        System.err.println(e);
                        System.exit(1);
                    }
                });
        destination.close();
    }

    public static void mergePathWithAPK1(ZipFile apk, ZipOutputStream destination) throws IOException {
        Enumeration sourceEntries = apk.entries();

        while(sourceEntries.hasMoreElements()) {
            ZipEntry sourceEntry = (ZipEntry)sourceEntries.nextElement();;
            String sourceEntryName = sourceEntry.getName();

            if (sourceEntryName.endsWith(".dex") && !sourceEntryName.split("/")[sourceEntryName.split("/").length - 1].startsWith("classes")) {

                if (!(copiedFileList.contains(sourceEntryName))) {

                    System.out.println(sourceEntryName);
                }
            } else
                continue;

            ZipEntry destinationEntry = new ZipEntry(sourceEntryName);
            destinationEntry.setMethod(sourceEntry.getMethod());
            destinationEntry.setSize(sourceEntry.getSize());
            destinationEntry.setCrc(sourceEntry.getCrc());
            destination.putNextEntry(destinationEntry);
            InputStream zipEntryInput = apk.getInputStream(sourceEntry);
            byte[] buffer = new byte[2048];

            for(int bytesRead = zipEntryInput.read(buffer); bytesRead > 0; bytesRead = zipEntryInput.read(buffer)) {
                destination.write(buffer, 0, bytesRead);
            }

            zipEntryInput.close();
        }

        destination.close();
    }
}
