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
 * Created by jayanga on 8/2/16.
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

    public Optional<SecretRepository> getSecretRepository() {
        return Optional.ofNullable(secretRepository);
    }

    public void setSecretRepository(SecretRepository secretRepository) {
        this.secretRepository = secretRepository;
    }

    public Optional<SecretRetriever> getSecretRetriever() {
        return Optional.ofNullable(secretRetriever);
    }

    public void setSecretRetriever(SecretRetriever secretRetriever) {
        this.secretRetriever = secretRetriever;
    }
}
