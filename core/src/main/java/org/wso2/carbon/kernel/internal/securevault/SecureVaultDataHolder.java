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

import org.wso2.carbon.kernel.securevault.SecretRepository;
import org.wso2.carbon.kernel.securevault.SecretRetriever;

import java.util.Optional;

/**
 * Secure Vault DataHolder.
 *
 * @since 5.2.0
 */
public class SecureVaultDataHolder {
    private static SecureVaultDataHolder instance = new SecureVaultDataHolder();
    private SecretRepository secretRepository;
    private SecretRetriever secretRetriever;

    public static SecureVaultDataHolder getInstance() {
        return instance;
    }

    private SecureVaultDataHolder() {
    }

    /**
     * Getter method of SecretRepository instance.
     *
     * @return Optional<SecretRepository> returns an {@link Optional} {@link SecretRepository} instance
     */
    public Optional<SecretRepository> getSecretRepository() {
        return Optional.ofNullable(secretRepository);
    }

    /**
     * Setter method of {@link SecretRepository}
     *
     * @param secretRepository SecretRepository instance to be set
     */
    public void setSecretRepository(SecretRepository secretRepository) {
        this.secretRepository = secretRepository;
    }

    /**
     * Getter method of SecretRetriever instance.
     *
     * @return Optional<SecretRetriever> returns an {@link Optional} {@link SecretRetriever} instance
     */
    public Optional<SecretRetriever> getSecretRetriever() {
        return Optional.ofNullable(secretRetriever);
    }

    /**
     * Setter method of {@link SecretRetriever}
     *
     * @param secretRetriever SecretRetriever instance to be set
     */
    public void setSecretRetriever(SecretRetriever secretRetriever) {
        this.secretRetriever = secretRetriever;
    }
}
