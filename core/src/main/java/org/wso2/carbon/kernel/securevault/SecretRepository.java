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

import org.wso2.carbon.kernel.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.util.List;

/**
 * Created by jayanga on 7/12/16.
 */
public interface SecretRepository {
    void init(SecureVaultConfiguration secureVaultConfiguration, CipherProvider cipherProvider, List<Secret> secrets)
            throws SecureVaultException;
    void loadSecrets(SecureVaultConfiguration secureVaultConfiguration, CipherProvider cipherProvider,
                       List<Secret> initializationSecrets) throws SecureVaultException;
    void persistSecrets(SecureVaultConfiguration secureVaultConfiguration, CipherProvider cipherProvider,
                        List<Secret> initializationSecrets) throws SecureVaultException;
    default void getInitializationSecrets(List<Secret> secrets) {}
    char[] getSecret(String alias);
}
