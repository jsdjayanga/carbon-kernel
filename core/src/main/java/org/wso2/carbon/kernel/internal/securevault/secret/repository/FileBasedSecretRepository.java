package org.wso2.carbon.kernel.internal.securevault.secret.repository;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.internal.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecretRepository;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.util.List;

/**
 * Created by jayanga on 7/12/16.
 */
@Component(
        name = "org.wso2.carbon.kernel.internal.securevault.secret.repository.FileBasedSecretRepository",
        immediate = true,
        property = {
                "capabilityName=SecretRepository",
                "secretRepositoryType=file"
        }
)
public class FileBasedSecretRepository implements SecretRepository {
    private static Logger logger = LoggerFactory.getLogger(FileBasedSecretRepository.class);

    @Activate
    public void activate() {
        logger.info("===================FileBasedSecretRepository activate");
    }

    @Deactivate
    public void deactivate() {
        logger.info("===================FileBasedSecretRepository deactivate");
    }

    @Override
    public void init(SecureVaultConfiguration secureVaultConfiguration, List<Secret> secrets)
            throws SecureVaultException {
        logger.info("===================initializing FileBasedSecretRepository");


        //String type = secretRepositoryConfig.getString("keystore", "secretProvider");


    }

    @Override
    public String getSecret(String alias) {
        return null;
    }
}
