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

package org.wso2.carbon.kernel.internal.securevault;

import org.osgi.framework.BundleContext;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

/**
 * Created by jayanga on 7/13/16.
 */
public class SecureVaultUtils {
    private static final Logger logger = LoggerFactory.getLogger(SecureVaultUtils.class);

    public static ServiceReference getServiceReference(BundleContext bundleContext, String propertyName,
                                                       String serviceClassName, String serviceName)
            throws SecureVaultException {
        ServiceReference[] serviceReferences;
        try {
            serviceReferences = bundleContext.getServiceReferences(serviceClassName, null);
        } catch (InvalidSyntaxException e) {
            throw new SecureVaultException("Error while retrieving OSGi service reference");
        }

        for (ServiceReference serviceReference : serviceReferences) {
            if (serviceName.equals(serviceReference.getProperty(propertyName))) {
                logger.info("Service provider '{}' found with given property '{}'", serviceName, propertyName);
                return serviceReference;
            }
        }

        throw new SecureVaultException("Unable to find an implementation for '" + serviceName
                + "' with property '" + propertyName + "'");
    }

    public static List<Secret> createSecrets(List<String> paramaters) {
        List<Secret> secrets = new ArrayList<>();
        for (String paramater : paramaters) {
            secrets.add(new Secret(paramater));
        }
        return secrets;
    }

    public static Secret getSecret(List<Secret> secrets, String secretName) throws SecureVaultException {
        for (Secret secret : secrets) {
            if (secret.getSecretName().equals(secretName)) {
                return secret;
            }
        }
        throw new SecureVaultException("No secret found with given secret name '" + secretName + "'");
    }

    public static byte[] base64Decode(String base64Encoded) {
        byte[] decodedValue = Base64.getDecoder().decode(base64Encoded);
        return decodedValue;
    }

    public static byte[] base64Encode(byte[] original) {
        byte[] encodedValue = Base64.getEncoder().encode(original);
        return encodedValue;
    }

    public static char[] toChars(byte[] bytes) {
        Charset charset = Charset.forName("UTF-8");
        return charset.decode(ByteBuffer.wrap(bytes)).array();
    }

    public static byte[] toBytes(char[] chars) {
        Charset charset = Charset.forName("UTF-8");
        return charset.encode(CharBuffer.wrap(chars)).array();
    }

    public static Properties loadSecretFile(Path secretsFilePath) throws SecureVaultException {
        Properties properties = new Properties();
        try (InputStream inputStream = new FileInputStream(secretsFilePath.toFile())) {

            // TODO : Use ConfigUtil to update with environment variables

            properties.load(inputStream);
        } catch (FileNotFoundException e) {
            throw new SecureVaultException("Cannot find secrets file in given location. (location: "
                    + secretsFilePath + ")", e);
        } catch (IOException e) {
            throw new SecureVaultException("Cannot access secrets file in given location. (location: "
                    + secretsFilePath + ")", e);
        }
        return properties;
    }

    public static void updateSecretFile(Path secretsFilePath, Properties properties) throws SecureVaultException {
        try (OutputStream outputStream = new FileOutputStream(secretsFilePath.toFile())) {
            properties.store(outputStream, null);
        } catch (FileNotFoundException e) {
            throw new SecureVaultException("Cannot find secrets file in given location. (location: "
                    + secretsFilePath + ")", e);
        } catch (IOException e) {
            throw new SecureVaultException("Cannot access secrets file in given location. (location: "
                    + secretsFilePath + ")", e);
        }
    }
}
