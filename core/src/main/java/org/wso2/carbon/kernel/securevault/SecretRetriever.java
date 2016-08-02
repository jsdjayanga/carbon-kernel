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
 * This interface is used to register SecretRetriever.
 *
 * An implementation of this interface should be registered as an OSGi service using the SecretRetriever interface.
 *
 * The implementation of this interface can be different from one SecretRepository to another depending on its
 * requirements and behaviour.
 *
 * @since 5.2.0
 */
public interface SecretRetriever {

    /**
     * An implementation of this method should initialize the SecretRetriever, so that it could perform the
     * {@code readSecrets}
     *
     * @param secureVaultConfiguration  {@link SecureVaultConfiguration}
     * @throws SecureVaultException     on error while trying to initializing the SecretRetriever
     */
    default void init(SecureVaultConfiguration secureVaultConfiguration) throws SecureVaultException {}

    /**
     * An implementation of this method should populate the secretValue of all the Secrets provided in the
     * initializationSecrets list.
     *
     * @param initializationSecrets a list of {@link Secret} with initialization secrets
     * @throws SecureVaultException on error while trying to initializing the SecretRetriever
     */
    void readSecrets(List<Secret> initializationSecrets) throws SecureVaultException;
}
