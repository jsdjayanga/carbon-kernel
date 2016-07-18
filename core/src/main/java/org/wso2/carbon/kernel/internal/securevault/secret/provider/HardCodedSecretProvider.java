package org.wso2.carbon.kernel.internal.securevault.secret.provider;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.internal.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecretProvider;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.util.List;

/**
 * Created by jayanga on 7/13/16.
 */
@Component(
        name = "org.wso2.carbon.kernel.internal.securevault.secret.provider.HardCodedSecretProvider",
        immediate = true,
        property = {
                "capabilityName=SecretProvider",
                "secretProviderName=hardCoded"
        }
)
public class HardCodedSecretProvider implements SecretProvider {
    private static Logger logger = LoggerFactory.getLogger(HardCodedSecretProvider.class);

    @Activate
    public void activate() {
        if (logger.isDebugEnabled()) {
            logger.debug("Activating {}", this.getClass().getName());
        }
    }

    @Deactivate
    public void deactivate() {
        if (logger.isDebugEnabled()) {
            logger.debug("Deactivating {}", this.getClass().getName());
        }
    }

    @Override
    public void provide(List<Secret> secrets) throws SecureVaultException {
        logger.debug("Providing hard coded secrets for 'masterPassword' and 'privateKeyPassword'");

        Secret masterPassword = SecureVaultUtils.getSecret(secrets, "masterPassword");
        masterPassword.setSecretValue("wso2carbon");

        Secret privateKeyPassword = SecureVaultUtils.getSecret(secrets, "privateKeyPassword");
        privateKeyPassword.setSecretValue("wso2carbon");

    }
}
