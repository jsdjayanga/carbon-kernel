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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.MasterKeyReader;
import org.wso2.carbon.kernel.securevault.SecretRepository;
import org.wso2.carbon.kernel.securevault.SecureVaultConstants;
import org.wso2.carbon.kernel.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

/**
 * Created by jayanga on 8/4/16.
 */
public abstract class AbstractSecretRepository implements SecretRepository {
    private static Logger logger = LoggerFactory.getLogger(AbstractSecretRepository.class);
    private final Map<String, char[]> secrets = new HashMap<>();

    @Override
    public void loadSecrets(SecureVaultConfiguration secureVaultConfiguration, MasterKeyReader masterKeyReader)
            throws SecureVaultException {
        logger.debug("Loading secrets to SecretRepository");
        loadDecryptedSecrets(secureVaultConfiguration);
    }

    @Override
    public void persistSecrets(SecureVaultConfiguration secureVaultConfiguration, MasterKeyReader masterKeyReader)
            throws SecureVaultException {
        logger.debug("Persisting secrets to SecretRepository");
        persistEncryptedSecrets(secureVaultConfiguration);
    }

    @Override
    public char[] getSecret(String alias) {
        char[] secret = secrets.get(alias);
        if (secret != null && secret.length != 0) {
            return secret;
        }
        return new char[0];
    }

    @Override
    public byte[] encrypt(byte[] plainText) throws SecureVaultException {
        return new byte[0];
    }

    @Override
    public byte[] decrypt(byte[] cipherText) throws SecureVaultException {
        return new byte[0];
    }

    protected void loadDecryptedSecrets(SecureVaultConfiguration secureVaultConfiguration)
            throws SecureVaultException {
        Properties secretsProperties = SecureVaultUtils.getSecretProperties(secureVaultConfiguration);

        for (Object alias : secretsProperties.keySet()) {
            String key = String.valueOf(alias);
            String secret = secretsProperties.getProperty(key);
            char[] decryptedPassword;
            String[] tokens = secret.split(SecureVaultConstants.SPACE);
            if (tokens.length != 2) {
                throw new SecureVaultException("Secret properties file contains an invalid entry at key : " + key);
            }

            if (SecureVaultConstants.CIPHER_TEXT.equals(tokens[0])) {
                byte[] base64Decoded = SecureVaultUtils.base64Decode(SecureVaultUtils.toBytes(tokens[1].toCharArray()));
                decryptedPassword = SecureVaultUtils.toChars(decrypt(base64Decoded));
            } else if (SecureVaultConstants.PLAIN_TEXT.equals(tokens[0])) {
                decryptedPassword = tokens[1].toCharArray();
            } else {
                throw new SecureVaultException("Unknown prefix in secrets file");
            }
            secrets.put(key, decryptedPassword);
        }
    }

    protected void persistEncryptedSecrets(SecureVaultConfiguration secureVaultConfiguration)
            throws SecureVaultException {
        Properties secretsProperties = SecureVaultUtils.getSecretProperties(secureVaultConfiguration);

        for (Object alias : secretsProperties.keySet()) {
            String key = String.valueOf(alias);
            String secret = secretsProperties.getProperty(key);

            byte[] encryptedPassword;
            String[] tokens = secret.split(SecureVaultConstants.SPACE);
            if (tokens.length != 2) {
                throw new SecureVaultException("Secret properties file contains an invalid entry at key : " + key);
            }

            if (SecureVaultConstants.PLAIN_TEXT.equals(tokens[0])) {
                encryptedPassword = SecureVaultUtils.base64Encode(
                        encrypt(SecureVaultUtils.toBytes(tokens[1].trim().toCharArray())));
                secretsProperties.setProperty(key, SecureVaultConstants.CIPHER_TEXT + " "
                        + new String(SecureVaultUtils.toChars(encryptedPassword)));
            }
        }

        String secretPropertiesFileLocation = SecureVaultUtils
                .getSecretPropertiesFileLocation(secureVaultConfiguration);
        SecureVaultUtils.updateSecretFile(Paths.get(secretPropertiesFileLocation), secretsProperties);
    }
}
