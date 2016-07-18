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
import java.util.Base64;
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
        try {
            cipher = Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException  e) {
            throw new SecureVaultException("Failed to get Cipher for algorithm '" + algorithm + "'", e);
        }

        PrivateKey privateKey = null;
        try {
            privateKey = (PrivateKey) keyStore.getKey(alias, privateKeyPassword);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new SecureVaultException("Failed to get private key for alias '" + alias + "'", e);
        }

        try {
            cipher.init(cipherMode, privateKey);
        } catch (InvalidKeyException e) {
            throw new SecureVaultException("Failed to initialize Cipher for mode '" + cipherMode + "'", e);
        }
    }

    protected static byte[] base64Decode(String base64Encoded) {
        byte[] decodedValue = Base64.getDecoder().decode(base64Encoded);
        return decodedValue;
    }
}
