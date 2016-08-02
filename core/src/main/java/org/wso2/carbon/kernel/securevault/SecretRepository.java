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
 * This interface is used to register SecretRepositories.
 *
 * An implementation of this interface should be registered as an OSGi service using the SecretRepository interface.
 *
 * The implementation of this interface can be different from one SecretRepository to another depending on its
 * requirements and behaviour.
 *
 * @since 5.2.0
 */
public interface SecretRepository {

    /**
     * This method will be called with a {@link SecureVaultConfiguration}, a {@link CipherProvider}
     * and a list of {@link Secret}s.
     *
     * An implementation of this interface should initialize the {@link SecretRepository}, which make the
     * SecretRepository ready for {@code loadSecrets} and {@code persistSecrets}
     *
     * @param secureVaultConfiguration {@link SecureVaultConfiguration}
     * @param secretRetriever          an initialized secret retriever {@link SecretRetriever}
     * @throws SecureVaultException    on error while trying to initializing the SecretRepository
     */
    void init(SecureVaultConfiguration secureVaultConfiguration, SecretRetriever secretRetriever)
            throws SecureVaultException;

    /**
     * An implementation of this method should load the secrets from underlying secret repository.
     *
     * @param secureVaultConfiguration {@link SecureVaultConfiguration}
     * @param secretRetriever          an initialized secret retriever {@link SecretRetriever}
     * @throws SecureVaultException    on error while trying to load secrets
     */
    void loadSecrets(SecureVaultConfiguration secureVaultConfiguration, SecretRetriever secretRetriever)
            throws SecureVaultException;

    /**
     * An implementation of this method should persist the secrets to the underlying secret repository.
     *
     * @param secureVaultConfiguration {@link SecureVaultConfiguration}
     * @param initializationSecrets    a list of {@link Secret} with initialization secrets
     * @throws SecureVaultException    on error while trying to persis secrets
     */
    void persistSecrets(SecureVaultConfiguration secureVaultConfiguration, List<Secret> initializationSecrets)
            throws SecureVaultException;

    /**
     * An implementation of this method should provide the plain text secret for a given alias.
     *
     * @param alias alias of the secret
     * @return      if the given alias is available, a char[] consisting the plain text secret else and empty char[]
     */
    char[] getSecret(String alias);

    EncryptionProvider getEncryptionProvider();

    DecryptionProvider getDecryptionProvider();
}
