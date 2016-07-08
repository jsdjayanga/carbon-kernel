package org.wso2.carbon.kernel.securevault.keystore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.SecureVaultException;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * Created by jayanga on 7/7/16.
 */
public class JKSKeyStoreLoader implements KeyStoreLoader {
    private static final Logger logger = LoggerFactory.getLogger(JKSKeyStoreLoader.class);
    private String keyStorePath;
    private String keyStorePassword;

    public JKSKeyStoreLoader(String keyStorePath, String keyStorePassword) throws SecureVaultException {
        if (keyStorePath == null || keyStorePath.isEmpty()) {
            throw new SecureVaultException("Keystore path should not be null or empty");
        }
        if (keyStorePassword == null || keyStorePassword.isEmpty()) {
            throw new SecureVaultException("KeyStorePassword should not be null or empty");
        }

        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
    }

    @Override
    public KeyStore getKeyStore() throws SecureVaultException {
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(keyStorePath))) {
            KeyStore keyStore;
            try {
                keyStore = KeyStore.getInstance(KeyStoreType.JKS.toString());
                keyStore.load(bufferedInputStream, keyStorePassword.toCharArray());
                return keyStore;
            } catch (CertificateException e) {
                throw new SecureVaultException("Failed to load certificates from keystore : '" + keyStorePath + "'", e);
            } catch (NoSuchAlgorithmException e) {
                throw new SecureVaultException("Failed to load keystore algorithm at : '" + keyStorePath + "'", e);
            } catch (KeyStoreException e) {
                throw new SecureVaultException("Failed to initialize keystore at : '" + keyStorePath + "'", e);
            }
        } catch (IOException e) {
            throw new SecureVaultException("Unable to find keystore at '" + keyStorePath + "'", e);
        }
    }
}
