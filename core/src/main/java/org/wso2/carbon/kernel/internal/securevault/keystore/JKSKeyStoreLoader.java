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

package org.wso2.carbon.kernel.internal.securevault.keystore;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * Created by jayanga on 7/17/16.
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
