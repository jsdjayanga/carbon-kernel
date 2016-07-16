package org.wso2.carbon.kernel.internal.securevault.secret.provider;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecretProvider;

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
        logger.info("===================HardCodedSecretProvider activate");
    }

    @Deactivate
    public void deactivate() {
        logger.info("===================HardCodedSecretProvider deactivate");
    }

    @Override
    public void provide(List<Secret> secrets) {
        logger.info("Providing hard coded secrets");
        for (Secret secret : secrets) {
            if (secret.getSecretName().equals("masterPassword")) {
                secret.setSecretValue("wso2carbon");
            } else if (secret.getSecretName().equals("privateKeyPassword")) {
                secret.setSecretValue("wso2carbon");
            }
        }
    }
}
