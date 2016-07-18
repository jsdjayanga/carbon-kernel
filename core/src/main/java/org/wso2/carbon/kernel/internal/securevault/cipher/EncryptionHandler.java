package org.wso2.carbon.kernel.internal.securevault.cipher;

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
public class EncryptionHandler extends CipherHandler {
    public EncryptionHandler(KeyStore keyStore, String alias, char[] privateKeyPassword,
                             String algorithm) throws SecureVaultException {
        super(keyStore, alias, privateKeyPassword, algorithm,  Cipher.DECRYPT_MODE);
    }

    public byte[] decrypt(String encryptedPassword) throws SecureVaultException {
        byte[] base64DecodedPassword = base64Decode(encryptedPassword);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        CipherOutputStream out = new CipherOutputStream(baos, cipher);

        InputStream inputStream = new ByteArrayInputStream(base64DecodedPassword);
        byte[] buffer = new byte[64];
        int length;
        try {
            while ((length = inputStream.read(buffer)) != -1) {
                out.write(buffer, 0, length);
            }
        } catch (IOException e) {
            throw new SecureVaultException("IOError when reading the input" +
                    " stream for cipher ", e);
        } finally {
            try {
                inputStream.close();
                out.flush();
                out.close();
            } catch (IOException ignored) {
                // ignore exception
            }
        }

        return baos.toByteArray();
    }
}
