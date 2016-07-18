package org.wso2.carbon.kernel.internal.securevault.cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by jayanga on 7/18/16.
 */
public abstract class CipherHandler {
    private static Logger logger = LoggerFactory.getLogger(CipherHandler.class);
    protected Cipher cipher;

    public CipherHandler(KeyStore keyStore, String alias, char[] privateKeyPassword, String algorithm,
                         int cipherMode) throws SecureVaultException {
        PrivateKey privateKey;
        try {
            privateKey = (PrivateKey) keyStore.getKey(alias, privateKeyPassword);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new SecureVaultException("Failed to get private key for alias '" + alias + "'", e);
        }

        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(cipherMode, privateKey);
            this.cipher = cipher;
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new SecureVaultException("Failed to initialize Cipher for mode '" + cipherMode + "'", e);
        }
    }
}
