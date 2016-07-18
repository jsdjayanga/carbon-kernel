package org.wso2.carbon.kernel.internal.securevault.keystore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.security.KeyStore;

/**
 * Created by jayanga on 7/17/16.
 */
public class KeyStoreProvider {
    private static final Logger logger = LoggerFactory.getLogger(KeyStoreProvider.class);
    private KeyStore keyStore;

    public KeyStoreProvider(KeyStoreType keystoreType, String keystoreLocation, String password)
            throws SecureVaultException {
        switch (keystoreType) {
            case JKS:
                KeyStoreLoader keyStoreLoader = new JKSKeyStoreLoader(keystoreLocation, password);
                keyStore = keyStoreLoader.getKeyStore();
                break;
            //TODO : Implement other keystore types
            default:
                throw new SecureVaultException("Unsupported keystore type : " + keystoreType);
        }
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }
}
