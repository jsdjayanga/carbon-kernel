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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;

/**
 * Created by jayanga on 7/18/16.
 */
public abstract class CipherHandler {
    private static Logger logger = LoggerFactory.getLogger(CipherHandler.class);
    protected Cipher cipher;

    public byte[] doCipher(byte[] original) throws SecureVaultException {
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
