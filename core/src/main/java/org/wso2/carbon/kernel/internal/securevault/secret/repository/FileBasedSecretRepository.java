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

package org.wso2.carbon.kernel.internal.securevault.secret.repository;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.internal.securevault.SecureVaultConstants;
import org.wso2.carbon.kernel.internal.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.internal.securevault.cipher.DecryptionHandler;
import org.wso2.carbon.kernel.internal.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.internal.securevault.keystore.KeyStoreProvider;
import org.wso2.carbon.kernel.internal.securevault.keystore.KeyStoreType;
import org.wso2.carbon.kernel.internal.utils.Utils;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecretRepository;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Created by jayanga on 7/12/16.
 */
@Component(
        name = "org.wso2.carbon.kernel.internal.securevault.secret.repository.FileBasedSecretRepository",
        immediate = true,
        property = {
                "capabilityName=SecretRepository",
                "secretRepositoryType=file"
        }
)
public class FileBasedSecretRepository implements SecretRepository {
    private static Logger logger = LoggerFactory.getLogger(FileBasedSecretRepository.class);
    private final Map<String, char[]> secrets = new HashMap<>();

    @Activate
    public void activate() {
        if (logger.isDebugEnabled()) {
            logger.debug("Activating {}", this.getClass().getName());
        }
    }

    @Deactivate
    public void deactivate() {
        if (logger.isDebugEnabled()) {
            logger.debug("Deactivating {}", this.getClass().getName());
        }
    }

    @Override
    public void init(SecureVaultConfiguration secureVaultConfiguration, List<Secret> secrets)
            throws SecureVaultException {
        logger.info("Initializing FileBasedSecretRepository");

        String secretPropertiesFileLocation = secureVaultConfiguration.getString(SecureVaultConstants.LOCATION);
        if (secretPropertiesFileLocation == null || secretPropertiesFileLocation.isEmpty()) {
            secretPropertiesFileLocation = Utils.getSecretsPropertiesLocation();
        }
        Properties secretsProperties = SecureVaultUtils.loadSecretFile(Paths.get(secretPropertiesFileLocation));


        String keystoreType = secureVaultConfiguration.getString(
                SecureVaultConstants.KEYSTORE, SecureVaultConstants.TYPE);
        String keystoreLocation = secureVaultConfiguration.getString(
                SecureVaultConstants.KEYSTORE, SecureVaultConstants.LOCATION);
        String privateKeyAlias = secureVaultConfiguration.getString(
                SecureVaultConstants.KEYSTORE, SecureVaultConstants.ALIAS);
        String algorithm = secureVaultConfiguration.getString(
                SecureVaultConstants.KEYSTORE, SecureVaultConstants.ALGORITHM);
        if (algorithm == null || algorithm.isEmpty()) {
            algorithm = SecureVaultConstants.RSA;
        }
        Secret masterPassword = SecureVaultUtils.getSecret(secrets, SecureVaultConstants.MASTER_PASSWORD);
        Secret privateKeyPassword = SecureVaultUtils.getSecret(secrets, SecureVaultConstants.PRIVATE_KEY_PASSWORD);

        KeyStoreProvider keyStoreProvider = new KeyStoreProvider(KeyStoreType.valueOf(keystoreType),
                keystoreLocation, masterPassword.getSecretValue());
        KeyStore keyStore = keyStoreProvider.getKeyStore();


        DecryptionHandler decryptionHandler = new DecryptionHandler(keyStore, privateKeyAlias,
                privateKeyPassword.getSecretValue().toCharArray(), algorithm);

        for (Object alias : secretsProperties.keySet()) {
            String key = String.valueOf(alias);
            String secret = secretsProperties.getProperty(key);
            char[] decryptedPassword;
            String[] tokens = secret.split(" ");
            if (SecureVaultConstants.CIPHER_TEXT.equals(tokens[0])) {
                decryptedPassword = SecureVaultUtils.toChars(decryptionHandler.decrypt(tokens[1].trim()));
            } else if (SecureVaultConstants.PLAIN_TEXT.equals(tokens[0])) {
                decryptedPassword = tokens[1].toCharArray();
            } else {
                throw new SecureVaultException("Unknown prefix in secrets file");
            }
            this.secrets.put(key, decryptedPassword);
        }
    }

    @Override
    public char[] getSecret(String alias) {
        char[] secret = secrets.get(alias);
        if (secret != null && secret.length != 0) {
            return secret;
        }
        return new char[0];
    }
}
