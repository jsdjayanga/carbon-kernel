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

package org.wso2.carbon.kernel.internal.securevault.retriever;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.internal.securevault.SecureVaultConstants;
import org.wso2.carbon.kernel.internal.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.internal.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecretRetriever;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.util.List;

/**
 * This service component is responsible for providing secrets to initialize the secret repositories. It has
 * hard coded passwords for 'keyStorePassword' and 'privateKeyPassword'
 * And this component registers a SecretProvider as an OSGi service.
 *
 * @since 5.2.0
 */
@Component(
        name = "org.wso2.carbon.kernel.internal.securevault.retriever.HardCodedSecretRetriever",
        immediate = true,
        property = {
                "capabilityName=SecretProvider",
                "secretRetrieverType=org.wso2.carbon.kernel.internal.securevault.retriever.HardCodedSecretRetriever"
        }
)
public class HardCodedSecretRetriever implements SecretRetriever {
    private static Logger logger = LoggerFactory.getLogger(HardCodedSecretRetriever.class);

    @Activate
    public void activate() {
        logger.debug("Activating HardCodedSecretRetriever");
    }

    @Deactivate
    public void deactivate() {
        logger.debug("Deactivating HardCodedSecretRetriever");
    }

    @Override
    public void init(SecureVaultConfiguration secretRepositoryConfig) throws SecureVaultException {
        // Nothing to initialize
    }

    @Override
    public void readSecrets(List<Secret> secrets) throws SecureVaultException {
        logger.debug("Providing hard coded secrets for 'keyStorePassword' and 'privateKeyPassword'");

        Secret keyStorePassword = SecureVaultUtils.getSecret(secrets, SecureVaultConstants.KEY_STORE_PASSWORD);
        keyStorePassword.setSecretValue("wso2carbon");

        Secret privateKeyPassword = SecureVaultUtils.getSecret(secrets, SecureVaultConstants.PRIVATE_KEY_PASSWORD);
        privateKeyPassword.setSecretValue("wso2carbon");
    }
}
