package org.wso2.carbon.kernel.internal.securevault.keystore;

import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.security.KeyStore;

/**
 * Created by jayanga on 7/17/16.
 */
public interface KeyStoreLoader {
    public KeyStore getKeyStore() throws SecureVaultException;
}
