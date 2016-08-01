/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.kernel.securevault.cipher;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.CipherProvider;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecureVaultConstants;
import org.wso2.carbon.kernel.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

/**
 * This service component is responsible for providing encryption and decryption capabilities based on the JKS.
 * And this component registers a CipherProvider as an OSGi service.
 *
 * @since 5.2.0
 */
@Component(
        name = "org.wso2.carbon.kernel.securevault.cipher.JKSBasedCipherProvider",
        immediate = true,
        property = {
                "cipherProviderType=org.wso2.carbon.kernel.securevault.cipher.JKSBasedCipherProvider"
        }
)
public class JKSBasedCipherProvider implements CipherProvider {
    private static Logger logger = LoggerFactory.getLogger(JKSBasedCipherProvider.class);
    private Cipher encryptionCipher;
    private Cipher decryptionCipher;

    @Activate
    public void activate() {
        logger.debug("Activating JKSBasedCipherProvider");
    }

    @Deactivate
    public void deactivate() {
        logger.debug("Deactivating JKSBasedCipherProvider");
    }

    @Override
    public void init(SecureVaultConfiguration secureVaultConfiguration, List<Secret> secrets)
            throws SecureVaultException {
        String keystoreLocation = secureVaultConfiguration.getString(
                SecureVaultConstants.CIPHER_PROVIDER, SecureVaultConstants.KEYSTORE, SecureVaultConstants.LOCATION)
                .orElseThrow(() -> new SecureVaultException("Key store location is mandatory"));

        String privateKeyAlias = secureVaultConfiguration.getString(
                SecureVaultConstants.CIPHER_PROVIDER, SecureVaultConstants.KEYSTORE, SecureVaultConstants.ALIAS)
                .orElseThrow(() -> new SecureVaultException("Private key alias is mandatory"));

        String algorithm = secureVaultConfiguration.getString(
                SecureVaultConstants.CIPHER_PROVIDER, SecureVaultConstants.ALGORITHM)
                .orElse(SecureVaultConstants.RSA);

        Secret keyStorePassword = SecureVaultUtils.getSecret(secrets, SecureVaultConstants.KEY_STORE_PASSWORD);
        Secret privateKeyPassword = SecureVaultUtils.getSecret(secrets, SecureVaultConstants.PRIVATE_KEY_PASSWORD);

        KeyStore keyStore = loadKeyStore(keystoreLocation, keyStorePassword.getSecretValue().toCharArray());

        encryptionCipher = getEncryptionCipher(keyStore, privateKeyAlias, algorithm);
        decryptionCipher = getDecryptionCipher(keyStore, privateKeyAlias, algorithm,
                privateKeyPassword.getSecretValue().toCharArray());
    }

    @Override
    public void getInitializationSecrets(List<Secret> secrets) {
        secrets.add(new Secret(SecureVaultConstants.KEY_STORE_PASSWORD));
        secrets.add(new Secret(SecureVaultConstants.PRIVATE_KEY_PASSWORD));
    }

    @Override
    public byte[] encrypt(byte[] plainText) throws SecureVaultException {
        byte[] encryptedPassword = doCipher(encryptionCipher, plainText);
        return SecureVaultUtils.base64Encode(encryptedPassword);
    }

    @Override
    public byte[] decrypt(byte[] cipherText) throws SecureVaultException {
        byte[] base64DecodedPassword = SecureVaultUtils.base64Decode(cipherText);
        return doCipher(decryptionCipher, base64DecodedPassword);
    }

    private KeyStore loadKeyStore(String keyStorePath, char[] keyStorePassword) throws SecureVaultException {
        try (BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(keyStorePath))) {
            KeyStore keyStore;
            try {
                keyStore = KeyStore.getInstance(SecureVaultConstants.JKS);
                keyStore.load(bufferedInputStream, keyStorePassword);
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

    private Cipher getEncryptionCipher(KeyStore keyStore, String alias, String algorithm)
            throws SecureVaultException {
        Certificate certificate;
        try {
            certificate = keyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new SecureVaultException("Failed to get certificate for alias '" + alias + "'", e);
        }

        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, certificate);
            return cipher;
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new SecureVaultException("Failed to initialize Cipher for mode '" + Cipher.ENCRYPT_MODE + "'", e);
        }
    }

    private Cipher getDecryptionCipher(KeyStore keyStore, String alias, String algorithm, char[] privateKeyPassword)
            throws SecureVaultException {
        PrivateKey privateKey;
        try {
            privateKey = (PrivateKey) keyStore.getKey(alias, privateKeyPassword);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new SecureVaultException("Failed to get private key for alias '" + alias + "'", e);
        }

        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher;
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new SecureVaultException("Failed to initialize Cipher for mode '" + Cipher.DECRYPT_MODE + "'", e);
        }
    }

    private byte[] doCipher(Cipher cipher, byte[] original) throws SecureVaultException {
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
             CipherOutputStream cipherOutputStream = new CipherOutputStream(byteArrayOutputStream, cipher);
             InputStream inputStream = new ByteArrayInputStream(original)
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
