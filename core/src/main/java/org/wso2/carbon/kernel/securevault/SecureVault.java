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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.repository.SecretRepository;
import org.wso2.carbon.kernel.securevault.repository.SecretRepositoryProvider;

import java.nio.file.Path;

/**
 * SecureVault
 *
 * @since 5.2.0
 */
public class SecureVault {
    private static final Logger logger = LoggerFactory.getLogger(SecureVault.class);
    private static final SecureVault INSTANCE = new SecureVault();
    private boolean initialized = false;
    private SecureVaultConfiguration secretRepositoryConfig = null;
    private SecretRepository secretRepository = null;

    private SecureVault() {
    }

    public static SecureVault getInstance() {
        return INSTANCE;
    }

    public void init(Path configFilePath) throws SecureVaultException {
        if (initialized) {
            logger.debug("SecureVault is already initialized");
            return;
        }

        secretRepositoryConfig = new SecureVaultConfiguration(configFilePath);
        SecretRepositoryProvider secretRepositoryProvider = new SecretRepositoryProvider(secretRepositoryConfig);
        secretRepository = secretRepositoryProvider.getSecretRepository();
    }

    public String getSecret(String alias) {
        if (!initialized || secretRepository == null) {
            logger.debug("There is no secret repository. Returning alias itself");
            return alias;
        }
        return secretRepository.getSecret(alias);
    }
}
