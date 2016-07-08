package org.wso2.carbon.kernel.securevault.repository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.SecureVaultException;
import org.wso2.carbon.kernel.securevault.config.SecureVaultConfiguration;

/**
 * Created by jayanga on 7/7/16.
 */
public class SecretRepositoryProvider {
    private static final Logger logger = LoggerFactory.getLogger(SecretRepositoryProvider.class);
    private SecretRepository secretRepository;

    public SecretRepositoryProvider(SecureVaultConfiguration secretRepositoryConfig) throws SecureVaultException {
        String repositoryClass = secretRepositoryConfig.getString("repository");
        if (repositoryClass.trim().isEmpty()) {
            throw new SecureVaultException("Repository is undefined.");
        }

        Class clazz;
        try {
            clazz = getClass().getClassLoader().loadClass(repositoryClass.trim());
        } catch (ClassNotFoundException e) {
            throw new SecureVaultException("Failed to load repository class ", e);
        }

        try {
            Object instance = clazz.newInstance();
            if (instance instanceof SecretRepository) {
                SecretRepository secretRepository = (SecretRepository) instance;
                secretRepository.init(secretRepositoryConfig);
                this.secretRepository = secretRepository;
            } else {
                throw new SecureVaultException("Invalid SecretRepository class, " +
                        clazz.getName() + " is not a SecretRepository");
            }
        } catch (InstantiationException | IllegalAccessException e) {
            throw new SecureVaultException("Unable to instantiate repository : " + clazz.getName(), e);
        }
    }

    public SecretRepository getSecretRepository() {
        return secretRepository;
    }
}
