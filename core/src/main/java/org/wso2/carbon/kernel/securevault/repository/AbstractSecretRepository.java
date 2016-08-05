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
        Properties secretsProperties = SecureVaultUtils.getSecretProperties(secureVaultConfiguration);

        for (Map.Entry<Object, Object> entry: secretsProperties.entrySet()) {
            String key = entry.getKey().toString().trim();
            String value = entry.getValue().toString().trim();

            char[] decryptedPassword;
            String[] tokens = value.split(SecureVaultConstants.SPACE);

            if (tokens.length != 2) {
                logger.error("Secret properties file contains an invalid entry at key : {}", key);
                continue;
            }

            if (SecureVaultConstants.CIPHER_TEXT.equals(tokens[0])) {
                byte[] base64Decoded = SecureVaultUtils.base64Decode(SecureVaultUtils.toBytes(tokens[1]));
                decryptedPassword = SecureVaultUtils.toChars(decrypt(base64Decoded));
            } else if (SecureVaultConstants.PLAIN_TEXT.equals(tokens[0])) {
                decryptedPassword = tokens[1].toCharArray();
            } else {
                logger.error("Unknown prefix in secrets file");
                continue;
            }
            secrets.put(key, decryptedPassword);
        }
    }

    @Override
    public void persistSecrets(SecureVaultConfiguration secureVaultConfiguration, MasterKeyReader masterKeyReader)
            throws SecureVaultException {
        logger.debug("Persisting secrets to SecretRepository");
        Properties secretsProperties = SecureVaultUtils.getSecretProperties(secureVaultConfiguration);

        for (Map.Entry<Object, Object> entry: secretsProperties.entrySet()) {
            String key = entry.getKey().toString().trim();
            String value = entry.getValue().toString().trim();

            byte[] encryptedPassword;
            String[] tokens = value.split(SecureVaultConstants.SPACE);
            if (tokens.length != 2) {
                logger.error("Secret properties file contains an invalid entry at key : {}", key);
                continue;
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

    @Override
    public char[] resolve(String alias) {
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
}
