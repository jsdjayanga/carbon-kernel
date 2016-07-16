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
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecretProvider;
import org.wso2.carbon.kernel.securevault.SecretRepository;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;
import org.wso2.carbon.kernel.startupresolver.RequiredCapabilityListener;

import java.util.List;

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

        SecureVaultConfiguration secureVaultConfiguration;
        try {
            secureVaultConfiguration = SecureVaultConfiguration.getInstance();
            String secretRepositoryType = secureVaultConfiguration
                    .getString(SecureVaultConstants.SECRET_REPOSITORY_TYPE);
            initializeSecretRepository(secretRepositoryType, secureVaultConfiguration);
            logger.info("Successfully initialized secure vault with secret repository : " + secretRepositoryType);
        } catch (SecureVaultException e) {
            logger.error("Failed to read secure vault configuration", e);
        }


    }

    private void initializeSecretRepository(String secretRepositoryType,
                                            SecureVaultConfiguration secureVaultConfiguration)
            throws SecureVaultException {
        BundleContext bundleContext = DataHolder.getInstance().getBundleContext();
        ServiceReference serviceReference = SecureVaultUtils.getServiceReference(bundleContext,
                SecureVaultConstants.SECRET_REPOSITORY_PROPERTY_NAME, SecretRepository.class.getName(),
                secretRepositoryType);
        secretRepository = (SecretRepository) bundleContext.getService(serviceReference);

        String secretProviderName = secureVaultConfiguration.getString(SecureVaultConstants.SECRET_PROVIDER, "name");
        //BundleContext bundleContext = DataHolder.getInstance().getBundleContext();
        ServiceReference serviceReference1 = SecureVaultUtils.getServiceReference(bundleContext,
                SecureVaultConstants.SECRET_PROVIDER_PROPERTY_NAME, SecretProvider.class.getName(), secretProviderName);
        SecretProvider secretProvider = (SecretProvider) bundleContext.getService(serviceReference1);
        List<String> params = SecureVaultConfiguration.getInstance()
                .getList(SecureVaultConstants.SECRET_PROVIDER, "params");
        List<Secret> secrets = SecureVaultUtils.createSecrets(params);
        secretProvider.provide(secrets);

        secretRepository.init(secureVaultConfiguration, secrets);

//        if (bundleContext != null) {
//            ServiceReference[] serviceReferences;
//            try {
//                serviceReferences = bundleContext.getServiceReferences(SecretRepository.class.getName(), null);
//            } catch (InvalidSyntaxException e) {
//                throw new SecureVaultException("Error while retrieving OSGi service reference");
//            }
//
//            for (ServiceReference serviceReference : serviceReferences) {
//                if (name.equals(serviceReference.getProperty(SecureVaultConstants.SECRET_REPOSITORY))) {
//                    secretRepository = (SecretRepository) bundleContext.getService(serviceReference);
//                    secretRepository.init(secureVaultConfiguration);
//                    logger.info("SecureVault initialized with secret repository : " + name);
//                    return;
//                }
//            }
//
//            throw new SecureVaultException("Failed to initialize secret repository : " + name);
//        }
    }
}
