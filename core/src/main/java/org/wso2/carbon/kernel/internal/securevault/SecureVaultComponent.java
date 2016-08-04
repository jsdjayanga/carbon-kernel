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

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.internal.DataHolder;
import org.wso2.carbon.kernel.securevault.SecretRepository;
import org.wso2.carbon.kernel.securevault.SecretRetriever;
import org.wso2.carbon.kernel.securevault.SecureVault;
import org.wso2.carbon.kernel.securevault.SecureVaultConstants;
import org.wso2.carbon.kernel.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;
import org.wso2.carbon.kernel.startupresolver.RequiredCapabilityListener;

import java.util.Map;
import java.util.Optional;

/**
 * This service component acts as a RequiredCapabilityListener for all the SecretRepositories, SecretRetrievers
 * and CipherProviders. Once those are available, this component choose which instance to be used, based on the
 * secure vault configuration and registered the SecureVault OSGi service, which can then be used by other components
 * for encryption and decryption.
 *
 * @since 5.2.0
 */
@Component(
        name = "org.wso2.carbon.kernel.internal.securevault.SecureVaultComponent",
        immediate = true,
        property = {
                "componentName=carbon-secure-vault"
        }
)
public class SecureVaultComponent implements RequiredCapabilityListener {
    private static final Logger logger = LoggerFactory.getLogger(SecureVaultComponent.class);

    private String secretRepositoryType;
    private String secretRetrieverType;

    public SecureVaultComponent() {
        Optional<SecureVaultConfiguration> optSecureVaultConfiguration;
        try {
            SecureVaultConfiguration secureVaultConfiguration = SecureVaultConfiguration.getInstance();
            secretRepositoryType = secureVaultConfiguration.getString(SecureVaultConstants.SECRET_REPOSITORY,
                    SecureVaultConstants.TYPE).orElse("");
            secretRetrieverType = secureVaultConfiguration.getString(SecureVaultConstants.SECRET_RETRIEVER,
                    SecureVaultConstants.TYPE).orElse("");
        } catch (SecureVaultException e) {
            logger.error("Error while acquiring secure vault configuration");
        }
    }

    @Activate
    public void activate() {
        logger.debug("Activating SecureVaultComponent");
    }

    @Deactivate
    public void deactivate() {
        logger.debug("Deactivating SecureVaultComponent");
    }

    @Override
    public void onAllRequiredCapabilitiesAvailable() {
        logger.debug("All required capabilities are available for SecureVaultComponent");
        initializeSecureVault();
    }

    @Reference(
            name = "secure.vault.secret.repository",
            service = SecretRepository.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unRegisterSecretRepository"
    )
    protected void registerSecretRepository(SecretRepository secretRepository, Map<String, Object> configs) {
        Optional.ofNullable(configs.get(SecureVaultConstants.SECRET_REPOSITORY_PROPERTY_NAME))
                .ifPresent(o -> {
                    if (o.toString().equals(secretRepositoryType)) {
                        SecureVaultDataHolder.getInstance().setSecretRepository(secretRepository);
                    }
                });
    }

    protected void unRegisterSecretRepository(SecretRepository secretRepository) {
        SecureVaultDataHolder.getInstance().getSecretRepository().ifPresent(currentSecretRepository -> {
            if (currentSecretRepository == secretRepository) {
                SecureVaultDataHolder.getInstance().setSecretRepository(null);
            }
        });
    }

    @Reference(
            name = "secure.vault.secret.retriever",
            service = SecretRetriever.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterSecretRetriever"
    )
    protected void registerSecretRetriever(SecretRetriever secretRetriever, Map<String, Object> configs) {
        Optional.ofNullable(configs.get(SecureVaultConstants.SECRET_RETRIEVER_PROPERTY_NAME))
                .ifPresent(o -> {
                    if (o.toString().equals(secretRetrieverType)) {
                        SecureVaultDataHolder.getInstance().setSecretRetriever(secretRetriever);
                    }
                });
    }

    protected void unregisterSecretRetriever(SecretRetriever secretRetriever) {
        SecureVaultDataHolder.getInstance().getSecretRepository().ifPresent(currentSecretRetriever -> {
            if (currentSecretRetriever == secretRetriever) {
                SecureVaultDataHolder.getInstance().setSecretRetriever(null);
            }
        });
    }

    private void initializeSecureVault() {
        try {
            logger.debug("Initializing the secure vault with, SecretRepositoryType={}, SecretRetrieverType={}",
                    secretRepositoryType, secretRetrieverType);
            SecureVaultConfiguration secureVaultConfiguration = SecureVaultConfiguration.getInstance();

            SecretRetriever secretRetriever = SecureVaultDataHolder.getInstance().getSecretRetriever()
                    .orElseThrow(() ->
                            new SecureVaultException("Cannot initialise secure vault without secret retriever"));
            SecretRepository secretRepository = SecureVaultDataHolder.getInstance().getSecretRepository()
                    .orElseThrow(() ->
                            new SecureVaultException("Cannot initialise secure vault without secret repository"));

            secretRetriever.init(secureVaultConfiguration);

            secretRepository.init(secureVaultConfiguration, secretRetriever);
            secretRepository.loadSecrets(secureVaultConfiguration, secretRetriever);

            Optional.ofNullable(DataHolder.getInstance().getBundleContext())
                    .ifPresent(bundleContext -> bundleContext
                            .registerService(SecureVault.class, new SecureVaultImpl(), null));
        } catch (SecureVaultException e) {
            logger.error("Failed to initialize Secure Vault.", e);
        }
    }
}
