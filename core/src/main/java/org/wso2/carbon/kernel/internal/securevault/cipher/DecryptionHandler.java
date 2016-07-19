package org.wso2.carbon.kernel.internal.securevault.cipher;

import org.wso2.carbon.kernel.internal.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;

/**
 * Created by jayanga on 7/18/16.
 */
public class DecryptionHandler extends CipherHandler {
    public DecryptionHandler(KeyStore keyStore, String alias, char[] privateKeyPassword,
                             String algorithm) throws SecureVaultException {
        super(keyStore, alias, privateKeyPassword, algorithm, Cipher.DECRYPT_MODE);
    }

    public byte[] decrypt(String encryptedPassword) throws SecureVaultException {
        byte[] base64DecodedPassword = SecureVaultUtils.base64Decode(encryptedPassword);

        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
             CipherOutputStream cipherOutputStream = new CipherOutputStream(byteArrayOutputStream, cipher);
             InputStream inputStream = new ByteArrayInputStream(base64DecodedPassword)
        ) {
            byte[] buffer = new byte[1024];
            int length;

            while ((length = inputStream.read(buffer)) != -1) {
                cipherOutputStream.write(buffer, 0, length);
            }
            cipherOutputStream.flush();
            cipherOutputStream.close();
            return byteArrayOutputStream.toByteArray();
        } catch (IOException e) {
            throw new SecureVaultException("Failed to decrypt the password", e);
        }
    }
}
