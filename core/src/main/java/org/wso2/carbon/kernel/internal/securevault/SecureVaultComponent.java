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

import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.internal.DataHolder;
import org.wso2.carbon.kernel.internal.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.CipherProvider;
import org.wso2.carbon.kernel.securevault.SecretRepository;
import org.wso2.carbon.kernel.securevault.SecretRetriever;
import org.wso2.carbon.kernel.securevault.SecureVault;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;
import org.wso2.carbon.kernel.startupresolver.RequiredCapabilityListener;

/**
 * Created by jayanga on 7/12/16.
 */
@Component(
        name = "org.wso2.carbon.kernel.internal.securevault.SecureVaultComponent",
        immediate = true,
        property = {
                "componentName=carbon-secure-vault-mgt"
        }
)
public class SecureVaultComponent implements RequiredCapabilityListener {
    private static final Logger logger = LoggerFactory.getLogger(SecureVaultComponent.class);
    private SecretRepository secretRepository = null;


    @Activate
    public void activate() {
        logger.debug("Activating SecureVault component");
    }

    @Deactivate
    public void deactivate() {
        logger.debug("Deactivating SecureVault component");
    }

    @Override
    public void onAllRequiredCapabilitiesAvailable() {
        logger.debug("All dependencies for SecureVaultComponent are ready.");
        initializeSecureVault();
    }

    private void initializeSecureVault() {
        try {
            SecureVaultConfiguration secureVaultConfiguration = SecureVaultConfiguration.getInstance();
            String secretRepositoryType = secureVaultConfiguration.getString("secretRepository", "type");
            String secretRetrieverType = secureVaultConfiguration.getString("secretRetriever", "type");
            String cipherProviderType = secureVaultConfiguration.getString("cipherProvider", "type");

            if (logger.isDebugEnabled()) {
                logger.debug("Initializing secure vault with, SecretRepository={}, SecretRetriever={}, " +
                        "CipherProvider={}", secretRepositoryType, secretRetrieverType, cipherProviderType);
            }

            BundleContext bundleContext = DataHolder.getInstance().getBundleContext();

            ServiceReference secretRetrieverSR = SecureVaultUtils.getServiceReference(bundleContext,
                    SecureVaultConstants.SECRET_RETRIEVER_PROPERTY_NAME, SecretRetriever.class.getName(),
                    secretRetrieverType);
            SecretRetriever secretRetriever = (SecretRetriever) bundleContext.getService(secretRetrieverSR);
            secretRetriever.init(secureVaultConfiguration);

            ServiceReference cipherProviderSR = SecureVaultUtils.getServiceReference(bundleContext,
                    SecureVaultConstants.CIPHER_PROVIDER_PROPERTY_NAME, CipherProvider.class.getName(),
                    cipherProviderType);
            CipherProvider cipherProvider = (CipherProvider) bundleContext.getService(cipherProviderSR);
            cipherProvider.init(secureVaultConfiguration, secretRetriever);

            ServiceReference secretRepositorySR = SecureVaultUtils.getServiceReference(bundleContext,
                    SecureVaultConstants.SECRET_REPOSITORY_PROPERTY_NAME, SecretRepository.class.getName(),
                    secretRepositoryType);
            secretRepository = (SecretRepository) bundleContext.getService(secretRepositorySR);
            secretRepository.init(secureVaultConfiguration, cipherProvider);

            bundleContext.registerService(SecureVault.class, new SecureVaultImpl(secretRepository), null);
        } catch (SecureVaultException e) {
            logger.error("Failed to initialize Secure Vault.", e);
        }
    }
}
