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

package org.wso2.carbon.kernel.securevault;

import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

/**
 * This interface is used to register CipherProviders. A CipherProvider is expected to provide
 * encryption and decryption functionality.
 *
 * An implementation of this interface should be registered as an OSGi service using the CipherProvider interface.
 *
 * The implementation of this interface can be different from one CipherProvider to another depending on its
 * requirements and behaviour.
 *
 * @since 5.2.0
 */
public interface CipherProvider {
    /**
     * An implementation of this method should provide the relevant encryption logic.
     *
     * @param plainText             plain text as a byte array
     * @return byte[]               cipher text
     * @throws SecureVaultException on an error while trying to encrypt.
     */
    byte[] encrypt(byte[] plainText) throws SecureVaultException;

    /**
     * An implementation of this method should provide the relevant decryption logic.
     *
     * @param cipherText            cipher text as a byte array
     * @return byte[]               plain text
     * @throws SecureVaultException on an error while trying to encrypt.
     */
    byte[] decrypt(byte[] cipherText) throws SecureVaultException;
}
