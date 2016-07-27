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

package org.wso2.carbon.kernel.internal.securevault.cipher;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.internal.securevault.SecureVaultConstants;
import org.wso2.carbon.kernel.internal.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.internal.securevault.cipher.jks.DecryptionHandler;
import org.wso2.carbon.kernel.internal.securevault.cipher.jks.EncryptionHandler;
import org.wso2.carbon.kernel.internal.securevault.cipher.jks.KeyStoreProvider;
import org.wso2.carbon.kernel.internal.securevault.cipher.jks.KeyStoreType;
import org.wso2.carbon.kernel.internal.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.CipherProvider;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecretRetriever;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by jayanga on 7/22/16.
 */
@Component(
        name = "org.wso2.carbon.kernel.internal.securevault.cipher.JKSBasedCipherProvider",
        immediate = true,
        property = {
                "capabilityName=CipherProvider",
                "cipherProviderType=jks"
        }
)
public class JKSBasedCipherProvider implements CipherProvider {
    private static Logger logger = LoggerFactory.getLogger(JKSBasedCipherProvider.class);
    DecryptionHandler decryptionHandler;
    EncryptionHandler encryptionHandler;
    @Activate
    public void activate() {
        logger.info("Activating {}", this.getClass().getName());
    }

    @Deactivate
    public void deactivate() {
        logger.info("Deactivating {}", this.getClass().getName());
    }

    @Override
    public void init(SecureVaultConfiguration secureVaultConfiguration, SecretRetriever secretRetriever)
            throws SecureVaultException {
        String keystoreType = secureVaultConfiguration.getString(
                SecureVaultConstants.CIPHER_PROVIDER, SecureVaultConstants.KEYSTORE, SecureVaultConstants.TYPE);
        String keystoreLocation = secureVaultConfiguration.getString(
                SecureVaultConstants.CIPHER_PROVIDER, SecureVaultConstants.KEYSTORE, SecureVaultConstants.LOCATION);
        String privateKeyAlias = secureVaultConfiguration.getString(
                SecureVaultConstants.CIPHER_PROVIDER, SecureVaultConstants.KEYSTORE, SecureVaultConstants.ALIAS);
        String algorithm = secureVaultConfiguration.getString(
                SecureVaultConstants.CIPHER_PROVIDER, SecureVaultConstants.KEYSTORE, SecureVaultConstants.ALGORITHM);
        if (algorithm == null || algorithm.isEmpty()) {
            algorithm = SecureVaultConstants.RSA;
        }

        List<Secret> secrets = new ArrayList<>();
        secrets.add(new Secret(SecureVaultConstants.MASTER_PASSWORD));
        secrets.add(new Secret(SecureVaultConstants.PRIVATE_KEY_PASSWORD));

        secretRetriever.readSecrets(secrets);

        Secret masterPassword = SecureVaultUtils.getSecret(secrets, SecureVaultConstants.MASTER_PASSWORD);
        Secret privateKeyPassword = SecureVaultUtils.getSecret(secrets, SecureVaultConstants.PRIVATE_KEY_PASSWORD);

        KeyStoreProvider keyStoreProvider = new KeyStoreProvider(KeyStoreType.valueOf(keystoreType),
                keystoreLocation, masterPassword.getSecretValue());
        KeyStore keyStore = keyStoreProvider.getKeyStore();

        decryptionHandler = new DecryptionHandler(keyStore, privateKeyAlias,
                privateKeyPassword.getSecretValue().toCharArray(), algorithm);

        encryptionHandler = new EncryptionHandler(keyStore, privateKeyAlias, algorithm);
    }

    @Override
    public byte[] encrypt(byte[] plainText) throws SecureVaultException {
        return encryptionHandler.encrypt(plainText);
    }

    @Override
    public byte[] decrypt(byte[] cipherText) throws SecureVaultException {
        return decryptionHandler.decrypt(cipherText);
    }
}
