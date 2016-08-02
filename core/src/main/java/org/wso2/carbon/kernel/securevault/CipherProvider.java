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
 * This interface is used to register CipherProviders. A CipherProvider is expected to provide
 * encryption and decryption functionality.
 *
 * An implementation of this interface should be registered as an OSGi service using the CipherProvider interface.
 *
 * The implementation of this interface can be different from one CipherProvider to another depending on its
 * requirements and behaviour.
 *
 * @since 5.2.0
 */
public interface CipherProvider {

    /**
     * This method will be called with a {@link SecureVaultConfiguration} and a list of {@link Secret}s.
     * An implementation of this interface can read configurations needed from the {@code secureVaultConfiguration} and
     * secrets to initialize the CipherProvider from {@code initializationSecrets}
     *
     * @param secureVaultConfiguration  {@link SecureVaultConfiguration}
     * @param initializationSecrets     a list of initialization secrets
     * @throws SecureVaultException     on error while trying to initializing the CipherProvider
     */
    void init(SecureVaultConfiguration secureVaultConfiguration, List<Secret> initializationSecrets)
            throws SecureVaultException;

    /**
     * An implementation of this method should add the {@link Secret}s that are needed for the initialization
     * to the list (only need to provide the secret name). The given secrets will be populated via a
     * {@link SecretRetriever} and will be provided back in the {@code init} method.
     *
     * @param initializationSecrets a list of secrets that is needed for CipherProvider to initialize {@link Secret}.
     */
    default void getInitializationSecrets(List<Secret> initializationSecrets) {}

    /**
     * An implementation of this method should provide the relevant encryption logic.
     *
     * @param plainText             plain text as a byte array
     * @return byte[]               cipher text
     * @throws SecureVaultException on an error while trying to encrypt.
     */
    byte[] encrypt(byte[] plainText) throws SecureVaultException;

    /**
     * An implementation of this method should provide the relevant decryption logic.
     *
     * @param cipherText            cipher text as a byte array
     * @return byte[]               plain text
     * @throws SecureVaultException on an error while trying to encrypt.
     */
    byte[] decrypt(byte[] cipherText) throws SecureVaultException;
}
