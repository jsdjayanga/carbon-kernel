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

package org.wso2.carbon.kernel.securevault.tool;

import org.wso2.carbon.kernel.internal.securevault.SecureVaultConfigurationProvider;
import org.wso2.carbon.kernel.securevault.MasterKeyReader;
import org.wso2.carbon.kernel.securevault.SecretRepository;
import org.wso2.carbon.kernel.securevault.SecureVaultConstants;
import org.wso2.carbon.kernel.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.securevault.config.model.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by jayanga on 7/18/16.
 */
public class CipherTool {
    private static final Logger logger = Logger.getLogger(CipherTool.class.getName());
    private SecureVaultConfiguration secureVaultConfiguration;
    private MasterKeyReader masterKeyReader;
    private SecretRepository secretRepository;
    private URLClassLoader urlClassLoader;

    public void run(String[] args, URLClassLoader urlClassLoader) {
        this.urlClassLoader = urlClassLoader;
        logger.info("####### WSO2 CipherTool #######");
        try {
            processArgs(args);
        } catch (SecureVaultException e) {
            logger.log(Level.SEVERE, "CipherTool exits with error", e);
        }
    }

    private void processArgs(String[] args) throws SecureVaultException {
        if (args.length == 0 || (args.length == 1 && args[0].startsWith(SecureVaultConstants.CUSTOM_LIB_PATH + "="))) {
            process();
        } else if (args[0].startsWith(SecureVaultConstants.ENCRYPT_TEXT + "=")) {
            encryptText(args[0].substring(12));
        } else if (args[0].startsWith(SecureVaultConstants.DECRYPT_TEXT + "=")) {
            decryptText(args[0].substring(12));
        } else {
            printHelp();
        }
    }

    private void init() throws SecureVaultException {
        secureVaultConfiguration = SecureVaultConfigurationProvider.getConfiguration();

        String secretRepositoryType = secureVaultConfiguration.getSecretRepositoryConfig().getType()
                .orElseThrow(() -> new SecureVaultException("Secret repository type is mandatory"));
        String masterKeyReaderType = secureVaultConfiguration.getMasterKeyReaderConfig().getType()
                .orElseThrow(() -> new SecureVaultException("Master key reader type is mandatory"));

        try {
            masterKeyReader = (MasterKeyReader) urlClassLoader.loadClass(masterKeyReaderType).newInstance();
            secretRepository = (SecretRepository) urlClassLoader.loadClass(secretRepositoryType).newInstance();
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            throw new SecureVaultException("Failed to instantiate implementation classes.", e);
        }

        masterKeyReader.init(secureVaultConfiguration.getMasterKeyReaderConfig());
        secretRepository.init(secureVaultConfiguration.getSecretRepositoryConfig(), masterKeyReader);
    }

    private void process() throws SecureVaultException {
        init();
        secretRepository.persistSecrets(secureVaultConfiguration.getSecretRepositoryConfig());
    }

    private void printHelp() {
        logger.info("==========help===========");
    }

    private void encryptText(String plainText) throws SecureVaultException {
        init();
        byte[] encryptedPassword = secretRepository.encrypt(SecureVaultUtils.toBytes(plainText.trim()));
        logger.info(new String(SecureVaultUtils.toChars(SecureVaultUtils.base64Encode(encryptedPassword))));
    }

    private void decryptText(String cipherText) throws SecureVaultException {
        init();
        byte[] decryptedPassword = secretRepository.decrypt(SecureVaultUtils
                .base64Decode(SecureVaultUtils.toBytes(cipherText)));
        logger.info(new String(SecureVaultUtils.toChars(decryptedPassword)));
    }
}
