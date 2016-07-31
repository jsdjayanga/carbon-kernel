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

package org.wso2.carbon.kernel.securevault;

import org.osgi.framework.BundleContext;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.internal.utils.Utils;
import org.wso2.carbon.kernel.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.io.ByteArrayOutputStream;
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
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Properties;

/**
 * Created by jayanga on 7/13/16.
 */
public class SecureVaultUtils {
    private static final Logger logger = LoggerFactory.getLogger(SecureVaultUtils.class);

    public static Optional<ServiceReference<?>> getServiceReference(BundleContext bundleContext, String propertyName,
                                                                     String serviceClassName, String serviceName)
            throws SecureVaultException {
        try {
            return Arrays.stream(Optional.ofNullable(bundleContext.getServiceReferences(serviceClassName,
                    "(" + propertyName + "=" + serviceName + ")")).orElse(new ServiceReference[0]))
                    .filter(serviceReference -> serviceName.equals(serviceReference.getProperty(propertyName)))
                    .findFirst();
        } catch (InvalidSyntaxException e) {
            throw new SecureVaultException("Error while retrieving OSGi service reference");
        }
    }

    public static Secret getSecret(List<Secret> secrets, String secretName) throws SecureVaultException {
        return secrets.stream()
                .filter(secret -> secret.getSecretName().equals(secretName))
                .findFirst()
                .orElseThrow(() -> new SecureVaultException(
                        "No secret found with given secret name '" + secretName + "'"));
    }

    public static byte[] base64Decode(byte[] base64Encoded) {
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
        ByteBuffer encoded = charset.encode(CharBuffer.wrap(chars));

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(encoded.array(), 0, encoded.limit());
        return byteArrayOutputStream.toByteArray();
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

    public static Properties getSecretProperties(SecureVaultConfiguration secureVaultConfiguration)
            throws SecureVaultException {
        String secretPropertiesFileLocation = getSecretPropertiesFileLocation(secureVaultConfiguration);
        Properties secretsProperties = SecureVaultUtils.loadSecretFile(Paths.get(secretPropertiesFileLocation));
        return secretsProperties;
    }

    public static String getSecretPropertiesFileLocation(SecureVaultConfiguration secureVaultConfiguration) {
        return secureVaultConfiguration.getString(SecureVaultConstants.SECRET_REPOSITORY, SecureVaultConstants.LOCATION)
                .orElse(Utils.getSecretsPropertiesLocation());
    }
}
