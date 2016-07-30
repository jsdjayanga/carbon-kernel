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
import org.wso2.carbon.kernel.internal.utils.Utils;
import org.wso2.carbon.kernel.securevault.CipherProvider;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecretRepository;
import org.wso2.carbon.kernel.securevault.SecureVaultConstants;
import org.wso2.carbon.kernel.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.nio.file.Paths;
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
        name = "org.wso2.carbon.kernel.securevault.repository.FileBasedSecretRepository",
        immediate = true,
        property = {
                "capabilityName=SecretRepository",
                "secretRepositoryType=org.wso2.carbon.kernel.securevault.repository.FileBasedSecretRepository"
        }
)
public class FileBasedSecretRepository implements SecretRepository {
    private static Logger logger = LoggerFactory.getLogger(FileBasedSecretRepository.class);
    private final Map<String, char[]> secrets = new HashMap<>();

    @Activate
    public void activate() {
        logger.debug("Activating FileBasedSecretRepository");
    }

    @Deactivate
    public void deactivate() {
        logger.debug("Deactivating FileBasedSecretRepository");
    }

    @Override
    public void init(SecureVaultConfiguration secureVaultConfiguration, CipherProvider cipherProvider,
                     List<Secret> secrets)
            throws SecureVaultException {
        logger.debug("Initializing FileBasedSecretRepository");

        Properties secretsProperties = getSecretProperties(secureVaultConfiguration);

        for (Object alias : secretsProperties.keySet()) {
            String key = String.valueOf(alias);
            String secret = secretsProperties.getProperty(key);
            char[] decryptedPassword;
            String[] tokens = secret.split(SecureVaultConstants.SPACE);
            if (SecureVaultConstants.CIPHER_TEXT.equals(tokens[0])) {
                decryptedPassword = SecureVaultUtils.toChars(cipherProvider
                        .decrypt(SecureVaultUtils.toBytes(tokens[1].trim().toCharArray())));
            } else if (SecureVaultConstants.PLAIN_TEXT.equals(tokens[0])) {
                decryptedPassword = tokens[1].toCharArray();
            } else {
                throw new SecureVaultException("Unknown prefix in secrets file");
            }
            this.secrets.put(key, decryptedPassword);
        }
    }

    @Override
    public void secureSecrets(SecureVaultConfiguration secureVaultConfiguration, CipherProvider cipherProvider,
                              List<Secret> secrets) throws SecureVaultException {
        logger.info("Securing FileBasedSecretRepository");

        Properties secretsProperties = getSecretProperties(secureVaultConfiguration);

        for (Object alias : secretsProperties.keySet()) {
            String key = String.valueOf(alias);
            String secret = secretsProperties.getProperty(key);

            byte[] encryptedPassword;
            String[] tokens = secret.split(SecureVaultConstants.SPACE);
            if (SecureVaultConstants.PLAIN_TEXT.equals(tokens[0])) {
                encryptedPassword = cipherProvider.encrypt(SecureVaultUtils.toBytes(tokens[1].trim().toCharArray()));
            } else if (SecureVaultConstants.CIPHER_TEXT.equals(tokens[0])) {
                encryptedPassword = SecureVaultUtils.toBytes(tokens[1].toCharArray());
            } else {
                throw new SecureVaultException("Unknown prefix in secrets file");
            }

            secretsProperties.setProperty(key, SecureVaultConstants.CIPHER_TEXT + " "
                    + new String(SecureVaultUtils.toChars(encryptedPassword)));
        }

        String secretPropertiesFileLocation = getSecretPropertiesFileLocation(secureVaultConfiguration);
        SecureVaultUtils.updateSecretFile(Paths.get(secretPropertiesFileLocation), secretsProperties);
    }

    @Override
    public char[] getSecret(String alias) {
        char[] secret = secrets.get(alias);
        if (secret != null && secret.length != 0) {
            return secret;
        }
        return new char[0];
    }

    private Properties getSecretProperties(SecureVaultConfiguration secureVaultConfiguration)
            throws SecureVaultException {
        String secretPropertiesFileLocation = getSecretPropertiesFileLocation(secureVaultConfiguration);
        Properties secretsProperties = SecureVaultUtils.loadSecretFile(Paths.get(secretPropertiesFileLocation));
        return secretsProperties;
    }

    private String getSecretPropertiesFileLocation(SecureVaultConfiguration secureVaultConfiguration) {
        return secureVaultConfiguration.getString(SecureVaultConstants.SECRET_REPOSITORY, SecureVaultConstants.LOCATION)
                .orElse(Utils.getSecretsPropertiesLocation());
    }
}
