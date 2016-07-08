package org.wso2.carbon.kernel.securevault.keystore;

import org.wso2.carbon.kernel.securevault.SecureVaultException;

import java.security.KeyStore;

/**
 * Created by jayanga on 7/7/16.
 */
public interface KeyStoreLoader {
    public KeyStore getKeyStore() throws SecureVaultException;
}
