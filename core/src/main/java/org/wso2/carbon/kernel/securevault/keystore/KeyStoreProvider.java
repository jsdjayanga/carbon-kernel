package org.wso2.carbon.kernel.securevault.keystore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.SecureVaultException;
import org.wso2.carbon.kernel.securevault.config.SecureVaultConfiguration;

import java.security.KeyStore;

/**
 * Created by jayanga on 7/7/16.
 */
public class KeyStoreProvider {
    private static final Logger logger = LoggerFactory.getLogger(KeyStoreProvider.class);
    private KeyStore keyStore;

    public KeyStoreProvider(SecureVaultConfiguration secretRepositoryConfig) throws SecureVaultException {
        if (!secretRepositoryConfig.exist("keystore")) {
            throw new SecureVaultException("Unable to find keystore configuration");
        }

        String type = secretRepositoryConfig.getString("keystore", "type");
        String location = secretRepositoryConfig.getString("keystore", "location");
        String password = secretRepositoryConfig.getString("keystore", "password");

        switch (KeyStoreType.valueOf(type)) {
            case JKS:
                KeyStoreLoader keyStoreLoader = new JKSKeyStoreLoader(location, password);
                keyStore = keyStoreLoader.getKeyStore();
                break;
                //TODO : Implement other keystore types
            default:
                throw new SecureVaultException("Unsupported keystore type : " + type);
        }
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }
}
