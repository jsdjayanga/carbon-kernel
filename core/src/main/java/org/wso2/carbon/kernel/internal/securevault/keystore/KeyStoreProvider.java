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

import java.security.KeyStore;

/**
 * Created by jayanga on 7/17/16.
 */
public class KeyStoreProvider {
    private static final Logger logger = LoggerFactory.getLogger(KeyStoreProvider.class);
    private KeyStore keyStore;

    public KeyStoreProvider(KeyStoreType keystoreType, String keystoreLocation, String password)
            throws SecureVaultException {
        switch (keystoreType) {
            case JKS:
                KeyStoreLoader keyStoreLoader = new JKSKeyStoreLoader(keystoreLocation, password);
                keyStore = keyStoreLoader.getKeyStore();
                break;
            //TODO : Implement other keystore types
            default:
                throw new SecureVaultException("Unsupported keystore type : " + keystoreType);
        }
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }
}
