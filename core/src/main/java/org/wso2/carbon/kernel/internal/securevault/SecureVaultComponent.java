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
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.internal.DataHolder;
import org.wso2.carbon.kernel.internal.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.CipherProvider;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecretRepository;
import org.wso2.carbon.kernel.securevault.SecretRetriever;
import org.wso2.carbon.kernel.securevault.SecureVault;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultRuntimeException;
import org.wso2.carbon.kernel.startupresolver.RequiredCapabilityListener;

import java.util.ArrayList;
import java.util.List;
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
    private ServiceRegistration secureVaultSReg = null;
    private SecretRepository activeSecretRepository = null;
    private SecretRetriever activeSecretRetriever = null;
    private CipherProvider activeCipherProvider = null;
    private List<SecretRepository> secretRepositories = new ArrayList<>();
    private List<SecretRetriever> secretRetrievers = new ArrayList<>();
    private List<CipherProvider> cipherProviders = new ArrayList<>();
    private boolean firstInitializationDone = false;
    private boolean initialized = false;

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
    protected void registerSecretRepository(SecretRepository secretRepository) {
        secretRepositories.add(secretRepository);
        if (firstInitializationDone == true && initialized == false) {
            initializeSecureVault();
        }
    }

    protected void unRegisterSecretRepository(SecretRepository secretRepository) {
        if (activeSecretRepository == secretRepository) {
            unInitializeSecureVault();
        }
        secretRepositories.remove(secretRepository);
    }

    @Reference(
            name = "secure.vault.secret.retriever",
            service = SecretRetriever.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterSecretRetriever"
    )
    protected void registerSecretRetriever(SecretRetriever secretRetriever) {
        secretRetrievers.add(secretRetriever);
        if (firstInitializationDone == true && initialized == false) {
            initializeSecureVault();
        }
    }

    protected void unregisterSecretRetriever(SecretRetriever secretRetriever) {
        if (activeSecretRetriever == secretRetriever) {
            unInitializeSecureVault();
        }
        secretRetrievers.remove(secretRetriever);
    }

    @Reference(
            name = "secure.vault.cipher.provider",
            service = CipherProvider.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterCipherProvider"
    )
    protected void registerCipherProvider(CipherProvider cipherProvider) {
        cipherProviders.add(cipherProvider);
        if (firstInitializationDone == true && initialized == false) {
            initializeSecureVault();
        }
    }

    protected void unregisterCipherProvider(CipherProvider cipherProvider) {
        if (activeCipherProvider == cipherProvider) {
            unInitializeSecureVault();
        }
        cipherProviders.remove(cipherProvider);
    }

    private void initializeSecureVault() {
        try {
            SecureVaultConfiguration secureVaultConfiguration = SecureVaultConfiguration.getInstance();
            String secretRepositoryType = secureVaultConfiguration.getString(SecureVaultConstants.SECRET_REPOSITORY,
                    SecureVaultConstants.TYPE).orElseThrow(() ->
                    new SecureVaultRuntimeException("Secret repository type is mandatory"));
            String secretRetrieverType = secureVaultConfiguration.getString(SecureVaultConstants.SECRET_RETRIEVER,
                    SecureVaultConstants.TYPE).orElseThrow(() ->
                    new SecureVaultRuntimeException("Secret retriever type is mandatory"));
            String cipherProviderType = secureVaultConfiguration.getString(SecureVaultConstants.CIPHER_PROVIDER,
                    SecureVaultConstants.TYPE).orElseThrow(() ->
                    new SecureVaultRuntimeException("Cipher provider type is mandatory"));

            logger.debug("Initializing the secure vault with, SecretRepositoryType={}, SecretRetrieverType={}, " +
                    "CipherProviderType={}", secretRepositoryType, secretRetrieverType, cipherProviderType);

            Optional<BundleContext> optBundleContext = Optional.ofNullable(
                    DataHolder.getInstance().getBundleContext());
            BundleContext bundleContext = optBundleContext.orElseThrow(() -> new SecureVaultRuntimeException(
                    "Unable to initialize secure vault as bundle context is null"));

            ServiceReference secretRetrieverSR = SecureVaultUtils.getServiceReference(bundleContext,
                    SecureVaultConstants.SECRET_RETRIEVER_PROPERTY_NAME, SecretRetriever.class.getName(),
                    secretRetrieverType);
            activeSecretRetriever = (SecretRetriever) bundleContext.getService(secretRetrieverSR);

            ServiceReference cipherProviderSR = SecureVaultUtils.getServiceReference(bundleContext,
                    SecureVaultConstants.CIPHER_PROVIDER_PROPERTY_NAME, CipherProvider.class.getName(),
                    cipherProviderType);
            activeCipherProvider = (CipherProvider) bundleContext.getService(cipherProviderSR);

            ServiceReference secretRepositorySR = SecureVaultUtils.getServiceReference(bundleContext,
                    SecureVaultConstants.SECRET_REPOSITORY_PROPERTY_NAME, SecretRepository.class.getName(),
                    secretRepositoryType);
            activeSecretRepository = (SecretRepository) bundleContext.getService(secretRepositorySR);

            List<Secret> secrets = new ArrayList<>();
            activeSecretRetriever.init(secureVaultConfiguration);
            activeCipherProvider.loadSecrets(secrets);
            activeSecretRepository.loadSecrets(secrets);
            activeSecretRetriever.readSecrets(secrets);

            activeCipherProvider.init(secureVaultConfiguration, secrets);
            activeSecretRepository.init(secureVaultConfiguration, activeCipherProvider, secrets);

            secureVaultSReg = bundleContext.registerService(SecureVault.class,
                    new SecureVaultImpl(activeSecretRepository), null);

            firstInitializationDone = true;
            initialized = true;
        } catch (SecureVaultException | SecureVaultRuntimeException e) {
            logger.error("Failed to initialize Secure Vault.", e);
        }
    }

    private void unInitializeSecureVault() {
        initialized = false;

        BundleContext bundleContext = DataHolder.getInstance().getBundleContext();
        bundleContext.ungetService(secureVaultSReg.getReference());

        secureVaultSReg = null;
        activeSecretRepository = null;
        activeSecretRetriever = null;
        activeCipherProvider = null;
    }
}
