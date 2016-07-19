package org.wso2.carbon.kernel.internal.securevault.cipher;

import org.wso2.carbon.kernel.internal.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by jayanga on 7/19/16.
 */
public class EncryptionHandler extends CipherHandler {

    public EncryptionHandler(KeyStore keyStore, String alias, String algorithm)
            throws SecureVaultException {

        Certificate certificate;
        try {
            certificate = keyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new SecureVaultException("Failed to get certificate for alias '" + alias + "'", e);
        }

        try {
            cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, certificate);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new SecureVaultException("Failed to initialize Cipher for mode '" + Cipher.ENCRYPT_MODE + "'", e);
        }
    }

    public byte[] encrypt(char[] plainTextPassword) throws SecureVaultException {
        byte[] encryptedPassword = doCipher(SecureVaultUtils.toBytes(plainTextPassword));
        return SecureVaultUtils.base64Encode(encryptedPassword);
    }
}
