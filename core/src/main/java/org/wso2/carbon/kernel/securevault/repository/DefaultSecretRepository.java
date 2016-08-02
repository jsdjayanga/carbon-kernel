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

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.CipherProvider;
import org.wso2.carbon.kernel.securevault.DecryptionProvider;
import org.wso2.carbon.kernel.securevault.EncryptionProvider;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecretRepository;
import org.wso2.carbon.kernel.securevault.SecretRetriever;
import org.wso2.carbon.kernel.securevault.SecureVaultConstants;
import org.wso2.carbon.kernel.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.securevault.cipher.JKSBasedCipherProvider;
import org.wso2.carbon.kernel.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * This service component is responsible for exposing the secrets given in the secrets.properties file. By default
 * this will read the secrets from default secrets.properties file. This can be altered by specifying "location"
 * of the secrets file in the secure_vault.yml file.
 * And this component registers a SecretRepository as an OSGi service.
 *
 * @since 5.2.0
 */
@Component(
        name = "org.wso2.carbon.kernel.securevault.repository.DefaultSecretRepository",
        immediate = true,
        property = {
                "capabilityName=org.wso2.carbon.kernel.securevault.SecretRepository",
                "secretRepositoryType=org.wso2.carbon.kernel.securevault.repository.DefaultSecretRepository"
        }
)
public class DefaultSecretRepository implements SecretRepository {
    private static Logger logger = LoggerFactory.getLogger(DefaultSecretRepository.class);
    private final Map<String, char[]> secrets = new HashMap<>();
    protected CipherProvider cipherProvider;

    @Activate
    public void activate() {
        logger.debug("Activating FileBasedSecretRepository");
    }

    @Deactivate
    public void deactivate() {
        logger.debug("Deactivating FileBasedSecretRepository");
    }

    @Override
    public void init(SecureVaultConfiguration secureVaultConfiguration, SecretRetriever secretRetriever)
            throws SecureVaultException {
        logger.debug("Initializing FileBasedSecretRepository");

        cipherProvider = createCipherProvider(secureVaultConfiguration, secretRetriever);
    }

    @Override
    public void loadSecrets(SecureVaultConfiguration secureVaultConfiguration, SecretRetriever secretRetriever)
            throws SecureVaultException {
        logger.debug("Loading secrets to FileBasedSecretRepository");
        loadDecryptedSecrets(secureVaultConfiguration, cipherProvider);
    }

    @Override
    public void persistSecrets(SecureVaultConfiguration secureVaultConfiguration, List<Secret> initializationSecrets)
            throws SecureVaultException {
        logger.debug("Securing FileBasedSecretRepository");
        persistEncryptedSecrets(secureVaultConfiguration, cipherProvider);
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
    public EncryptionProvider getEncryptionProvider() {
        return cipherProvider;
    }

    @Override
    public DecryptionProvider getDecryptionProvider() {
        return cipherProvider;
    }

    protected CipherProvider createCipherProvider(SecureVaultConfiguration secureVaultConfiguration,
                                               SecretRetriever secretRetriever) throws SecureVaultException {
        List<Secret> initializationSecrets = new ArrayList<>();
        initializationSecrets.add(new Secret(SecureVaultConstants.KEY_STORE_PASSWORD));
        initializationSecrets.add(new Secret(SecureVaultConstants.PRIVATE_KEY_PASSWORD));
        secretRetriever.readSecrets(initializationSecrets);

        CipherProvider cipherProvider = new JKSBasedCipherProvider();
        cipherProvider.init(secureVaultConfiguration, initializationSecrets);
        return cipherProvider;
    }

    protected char[] decryptSecret(String key, byte[] cipherText, CipherProvider cipherProvider)
            throws SecureVaultException {
        return SecureVaultUtils.toChars(cipherProvider.decrypt(cipherText));
    }

    protected byte[] encryptSecret(String key, char[] plainText, CipherProvider cipherProvider)
            throws SecureVaultException {
        return cipherProvider.encrypt(SecureVaultUtils.toBytes(plainText));
    }

    protected void loadDecryptedSecrets(SecureVaultConfiguration secureVaultConfiguration,
                                        CipherProvider cipherProvider) throws SecureVaultException {
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
            if (tokens.length != 2) {
                throw new SecureVaultException("Secret properties file contains an invalid entry at key : " + key);
            }

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
}
