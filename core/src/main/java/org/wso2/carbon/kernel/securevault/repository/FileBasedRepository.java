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

package org.wso2.carbon.kernel.securevault.repository;

import org.wso2.carbon.kernel.securevault.CipherProvider;
import org.wso2.carbon.kernel.securevault.SecureVaultConstants;
import org.wso2.carbon.kernel.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.nio.file.Paths;
import java.util.Map;
import java.util.Properties;

/**
 * Created by jayanga on 8/1/16.
 */
public abstract class FileBasedRepository {
    protected void loadDecryptedSecrets(SecureVaultConfiguration secureVaultConfiguration,
                                        CipherProvider cipherProvider,
                                        Map<String, char[]> secrets) throws SecureVaultException {
        Properties secretsProperties = SecureVaultUtils.getSecretProperties(secureVaultConfiguration);

        for (Object alias : secretsProperties.keySet()) {
            String key = String.valueOf(alias);
            String secret = secretsProperties.getProperty(key);
            char[] decryptedPassword;
            String[] tokens = secret.split(SecureVaultConstants.SPACE);
            if (SecureVaultConstants.CIPHER_TEXT.equals(tokens[0])) {
                byte[] base64Decoded = SecureVaultUtils.base64Decode(SecureVaultUtils.toBytes(tokens[1].toCharArray()));
                decryptedPassword = decryptSecret(key, base64Decoded, cipherProvider);
            } else if (SecureVaultConstants.PLAIN_TEXT.equals(tokens[0])) {
                decryptedPassword = tokens[1].toCharArray();
            } else {
                throw new SecureVaultException("Unknown prefix in secrets file");
            }
            secrets.put(key, decryptedPassword);
        }
    }

    protected void persistEncryptedSecrets(SecureVaultConfiguration secureVaultConfiguration,
                                           CipherProvider cipherProvider) throws SecureVaultException {
        Properties secretsProperties = SecureVaultUtils.getSecretProperties(secureVaultConfiguration);

        for (Object alias : secretsProperties.keySet()) {
            String key = String.valueOf(alias);
            String secret = secretsProperties.getProperty(key);

            byte[] encryptedPassword;
            String[] tokens = secret.split(SecureVaultConstants.SPACE);
            if (SecureVaultConstants.PLAIN_TEXT.equals(tokens[0])) {
                encryptedPassword = SecureVaultUtils.base64Encode(
                        encryptSecret(key, tokens[1].trim().toCharArray(), cipherProvider));
                secretsProperties.setProperty(key, SecureVaultConstants.CIPHER_TEXT + " "
                        + new String(SecureVaultUtils.toChars(encryptedPassword)));
            }
        }

        String secretPropertiesFileLocation = SecureVaultUtils
                .getSecretPropertiesFileLocation(secureVaultConfiguration);
        SecureVaultUtils.updateSecretFile(Paths.get(secretPropertiesFileLocation), secretsProperties);
    }

    protected abstract char[] decryptSecret(String key, byte[] cipherText, CipherProvider cipherProvider)
            throws SecureVaultException;

    protected abstract byte[] encryptSecret(String key, char[] plainText, CipherProvider cipherProvider)
            throws SecureVaultException;
}
