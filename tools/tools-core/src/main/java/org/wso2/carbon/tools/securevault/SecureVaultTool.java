/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.tools.securevault;

import org.wso2.carbon.tools.CarbonTool;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Paths;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * The Java class which defines the tool for SecureVault.
 *
 * @since 5.2.0
 */
public class SecureVaultTool implements CarbonTool {
    private static final Logger logger = Logger.getLogger(SecureVaultTool.class.getName());

    @Override
    public void execute(String... toolArgs) {
        List<URL> urls = new ArrayList<>();

        Stream.of(toolArgs)
                .filter(s -> s.startsWith("customLibPath"))
                .findFirst()
                .map(s1 -> s1.substring(14))
                .map(s2 -> Paths.get(s2))
                .filter(path -> path.toFile().exists() && path.toFile().isDirectory())
                .ifPresent(path1 -> urls.addAll(getJarURLs(path1.toString())));

        Optional.ofNullable(System.getProperty("carbon.home"))
                .ifPresent(carbonHome -> {
                    urls.addAll(getJarURLs(Paths.get(carbonHome, "osgi", "dropins").toString()));
                    urls.addAll(getJarURLs(Paths.get(carbonHome, "osgi", "plugins").toString()));
                });

        URLClassLoader urlClassLoader = (URLClassLoader) AccessController
                .doPrivileged((PrivilegedAction<Object>) () -> new URLClassLoader(urls.toArray(new URL[urls.size()])));


        try {
            Class clazz = urlClassLoader.loadClass("org.wso2.carbon.kernel.securevault.tool.CipherTool");
            Object object = clazz.newInstance();
            Method method = object.getClass().getMethod("run", String[].class, URLClassLoader.class);
            method.invoke(object, new Object[]{toolArgs, urlClassLoader});
            //cipherTool.init(urlClassLoader);
            //logger.info(clazz.getName() + cipherTool.getClass());
        } catch (ClassNotFoundException e) {
            logger.log(Level.SEVERE, "Error when executing the secure vault tool", e);
        } catch (InstantiationException e) {
            logger.log(Level.SEVERE, "CipherTool exits with error", e);
        } catch (IllegalAccessException e) {
            logger.log(Level.SEVERE, "CipherTool exits with error", e);
        } catch (NoSuchMethodException e) {
            logger.log(Level.SEVERE, "CipherTool exits with error", e);
        } catch (InvocationTargetException e) {
            logger.log(Level.SEVERE, "CipherTool exits with error", e);
        }
    }

    private List<URL> getJarURLs(String location) {
        File fileLocation = new File(location);
        List<URL> urls = new ArrayList<>();
        File[] fileList = fileLocation.listFiles((File file) -> file.getPath().toLowerCase().endsWith(".jar"));
        if (fileList != null) {
            for (File file : fileList) {
                urls.addAll(getInternalJarURLs(file));
            }
        }
        return urls;
    }

    private List<URL> getInternalJarURLs(File file) {
        List<URL> urls = new ArrayList<>();

        try (JarFile jarFile = new JarFile(file)) {
            urls.add(file.getAbsoluteFile().toURI().toURL());
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".jar")) {
                    JarEntry internalJar = jarFile.getJarEntry(entry.getName());
                    try (InputStream inputStream = jarFile.getInputStream(internalJar)) {
                        File tempFile = File.createTempFile(internalJar.getName(), ".tmp");
                        tempFile.deleteOnExit();
                        try (FileOutputStream fileOutputStream = new FileOutputStream(tempFile)) {
                            byte[] buffer = new byte[1024];
                            int length;
                            while ((length = inputStream.read(buffer)) != -1) {
                                fileOutputStream.write(buffer, 0, length);
                            }
                        }
                        urls.add(tempFile.getAbsoluteFile().toURI().toURL());
                    }
                }
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "CipherTool exits with error", e);
        }

        return urls;
    }
}
