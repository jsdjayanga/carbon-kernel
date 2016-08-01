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
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecretRepository;
import org.wso2.carbon.kernel.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
                "secretRepositoryType=org.wso2.carbon.kernel.securevault.repository.DefaultSecretRepository"
        }
)
public class DefaultSecretRepository extends FileBasedRepository implements SecretRepository {
    private static Logger logger = LoggerFactory.getLogger(DefaultSecretRepository.class);
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
    }

    @Override
    public void loadSecrets(SecureVaultConfiguration secureVaultConfiguration, CipherProvider cipherProvider,
                            List<Secret> initializationSecrets) throws SecureVaultException {
        logger.debug("Loading secrets to FileBasedSecretRepository");
        super.loadDecryptedSecrets(secureVaultConfiguration, cipherProvider, secrets);
    }

    @Override
    public void persistSecrets(SecureVaultConfiguration secureVaultConfiguration, CipherProvider cipherProvider,
                               List<Secret> initializationSecrets) throws SecureVaultException {
        logger.debug("Securing FileBasedSecretRepository");
        super.persistEncryptedSecrets(secureVaultConfiguration, cipherProvider);
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
    protected char[] decryptSecret(String key, char[] cipherText, CipherProvider cipherProvider)
            throws SecureVaultException {
        return SecureVaultUtils.toChars(cipherProvider.decrypt(SecureVaultUtils.toBytes(cipherText)));
    }

    @Override
    protected byte[] encryptSecret(String key, char[] plainText, CipherProvider cipherProvider)
            throws SecureVaultException {
        return cipherProvider.encrypt(SecureVaultUtils.toBytes(plainText));
    }
}
