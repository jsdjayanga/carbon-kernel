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

package org.wso2.carbon.kernel.internal.securevault.tool;

import org.wso2.carbon.kernel.internal.securevault.SecureVaultConstants;
import org.wso2.carbon.kernel.internal.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.internal.securevault.cipher.EncryptionHandler;
import org.wso2.carbon.kernel.internal.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.internal.securevault.keystore.KeyStoreProvider;
import org.wso2.carbon.kernel.internal.securevault.keystore.KeyStoreType;
import org.wso2.carbon.kernel.internal.securevault.secret.provider.DefaultSecretProvider;
import org.wso2.carbon.kernel.internal.utils.Utils;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecretProvider;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by jayanga on 7/18/16.
 */
public class CipherTool {
    private static final Logger logger = Logger.getLogger(CipherTool.class.getName());
    private SecureVaultConfiguration secureVaultConfiguration;
    private List<Secret> secrets;
    EncryptionHandler encryptionHandler;

    public static void main(String[] args) {
        logger.info("####### WSO2 CipherTool #######");
        CipherTool cipherTool;
        try {
            cipherTool = new CipherTool();
            if (args.length == 0) {
                cipherTool.encryptSecretsProperties();
            } else {
                cipherTool.processArgs(args);
            }
        } catch (SecureVaultException e) {
            logger.log(Level.SEVERE, "CipherTool exits with error", e);
        }
    }

    public CipherTool() throws SecureVaultException {
        secureVaultConfiguration = SecureVaultConfiguration.getInstance();

        SecretProvider secretProvider = new DefaultSecretProvider();
        secrets = new ArrayList<>();
        secrets.add(new Secret(SecureVaultConstants.MASTER_PASSWORD));
        secretProvider.provide(secrets);

        String keystoreType = secureVaultConfiguration.getString(
                SecureVaultConstants.KEYSTORE, SecureVaultConstants.TYPE);
        String keystoreLocation = secureVaultConfiguration.getString(
                SecureVaultConstants.KEYSTORE, SecureVaultConstants.LOCATION);
        String privateKeyAlias = secureVaultConfiguration.getString(
                SecureVaultConstants.KEYSTORE, SecureVaultConstants.ALIAS);
        String algorithm = secureVaultConfiguration.getString(
                SecureVaultConstants.KEYSTORE, SecureVaultConstants.ALGORITHM);
        if (algorithm == null || algorithm.isEmpty()) {
            algorithm = SecureVaultConstants.RSA;
        }

        KeyStoreProvider keyStoreProvider = new KeyStoreProvider(KeyStoreType.valueOf(keystoreType),
                keystoreLocation, SecureVaultUtils.getSecret(secrets,
                SecureVaultConstants.MASTER_PASSWORD).getSecretValue());
        KeyStore keyStore = keyStoreProvider.getKeyStore();
        encryptionHandler = new EncryptionHandler(keyStore, privateKeyAlias, algorithm);
    }

    private void encryptSecretsProperties() throws SecureVaultException {
        String secretPropertiesFileLocation = secureVaultConfiguration.getString(SecureVaultConstants.LOCATION);
        if (secretPropertiesFileLocation == null || secretPropertiesFileLocation.isEmpty()) {
            secretPropertiesFileLocation = Utils.getSecretsPropertiesLocation();
        }
        Properties secretsProperties = SecureVaultUtils.loadSecretFile(Paths.get(secretPropertiesFileLocation));

        for (Object alias : secretsProperties.keySet()) {
            String key = String.valueOf(alias);
            String encryptedText = secretsProperties.getProperty(key);

            String[] tokens = encryptedText.split(" ");
            if (SecureVaultConstants.PLAIN_TEXT.equals(tokens[0])) {
                byte[] encryptedPassword = encryptionHandler.encrypt(tokens[1].trim().toCharArray());
                secretsProperties.setProperty(key, SecureVaultConstants.CIPHER_TEXT + " "
                        + new String(SecureVaultUtils.toChars(encryptedPassword)));
            }
        }

        SecureVaultUtils.updateSecretFile(Paths.get(secretPropertiesFileLocation), secretsProperties);
    }

    private void processArgs(String[] args) throws SecureVaultException {
        if ("-help".equals(args[0])) {
            printHelp();
        } else if ((args[0].startsWith("-D" + SecureVaultConstants.ENCRYPT_TEXT + "="))) {
            encryptText(args[0].substring(14));
        } else {
            throw new SecureVaultException("Unknown option '" + args[0] + "'");
        }
    }

    private void printHelp() {
        logger.info("==========help===========");
    }

    private void encryptText(String plainText) throws SecureVaultException {
        byte[] encryptedPassword = encryptionHandler.encrypt(plainText.trim().toCharArray());
        logger.info(new String(SecureVaultUtils.toChars(encryptedPassword)));
    }
}
