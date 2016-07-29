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
import org.wso2.carbon.kernel.internal.securevault.config.SecureVaultConfiguration;
import org.wso2.carbon.kernel.securevault.CipherProvider;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.SecretRepository;
import org.wso2.carbon.kernel.securevault.SecretRetriever;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by jayanga on 7/18/16.
 */
public class CipherTool {
    private static final Logger logger = Logger.getLogger(CipherTool.class.getName());
    private SecureVaultConfiguration secureVaultConfiguration;
    private SecretRetriever secretRetriever;
    private CipherProvider cipherProvider;
    private SecretRepository secretRepository;
    List<Secret> secrets = new ArrayList<>();

    public static void main(String[] args) {
        logger.info("####### WSO2 CipherTool #######");
        try {
            CipherTool cipherTool = new CipherTool();
            cipherTool.init();
            cipherTool.processArgs(args);
        } catch (SecureVaultException e) {
            logger.log(Level.SEVERE, "CipherTool exits with error", e);
        }
    }

    private void init() throws SecureVaultException {
        secureVaultConfiguration = SecureVaultConfiguration.getInstance();

        String secretRepositoryType = secureVaultConfiguration.getString(SecureVaultConstants.SECRET_REPOSITORY,
                SecureVaultConstants.TYPE);
        String secretRetrieverType = secureVaultConfiguration.getString(SecureVaultConstants.SECRET_RETRIEVER,
                SecureVaultConstants.TYPE);
        String cipherProviderType = secureVaultConfiguration.getString(SecureVaultConstants.CIPHER_PROVIDER,
                SecureVaultConstants.TYPE);

        try {
            secretRetriever = (SecretRetriever) Class.forName(secretRetrieverType).newInstance();
            cipherProvider = (CipherProvider) Class.forName(cipherProviderType).newInstance();
            secretRepository = (SecretRepository) Class.forName(secretRepositoryType).newInstance();
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            throw new SecureVaultException("Failed to instantiate implementation classes.", e);
        }

        secretRetriever.init(secureVaultConfiguration);
        cipherProvider.loadSecrets(secrets);
        secretRepository.loadSecrets(secrets);
        secretRetriever.readSecrets(secrets);

        cipherProvider.init(secureVaultConfiguration, secrets);
    }

    private void process() throws SecureVaultException  {
        secretRepository.secureSecrets(secureVaultConfiguration, cipherProvider, secrets);
    }

    private void processArgs(String[] args) throws SecureVaultException {

        if (args.length == 0) {
            process();
        } else if ("-help".equals(args[0]) || "--help".equals(args[0])) {
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
        byte[] encryptedPassword = cipherProvider.encrypt(SecureVaultUtils.toBytes(
                plainText.trim().toCharArray()));
        logger.info(new String(SecureVaultUtils.toChars(encryptedPassword)));
    }
}
