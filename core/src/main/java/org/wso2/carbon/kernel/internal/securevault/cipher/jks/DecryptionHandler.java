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

package org.wso2.carbon.kernel.internal.securevault.cipher.jks;

import org.wso2.carbon.kernel.internal.securevault.SecureVaultUtils;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by jayanga on 7/18/16.
 */
public class DecryptionHandler extends CipherHandler {
    public DecryptionHandler(KeyStore keyStore, String alias, char[] privateKeyPassword,
                             String algorithm) throws SecureVaultException {
        PrivateKey privateKey;
        try {
            privateKey = (PrivateKey) keyStore.getKey(alias, privateKeyPassword);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new SecureVaultException("Failed to get private key for alias '" + alias + "'", e);
        }

        try {
            cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new SecureVaultException("Failed to initialize Cipher for mode '" + Cipher.DECRYPT_MODE + "'", e);
        }
    }

    public byte[] decrypt(byte[] encryptedPassword) throws SecureVaultException {
        byte[] base64DecodedPassword = SecureVaultUtils.base64Decode(encryptedPassword);
        return doCipher(base64DecodedPassword);
    }
}
