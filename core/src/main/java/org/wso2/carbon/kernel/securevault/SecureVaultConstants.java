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

/**
 * Secure Vault Constants.
 *
 * @since 5.2.0
 */
public class SecureVaultConstants {

    public static final String CIPHER_TEXT = "cipherText";
    public static final String PLAIN_TEXT = "plainText";
    public static final String ENCRYPT_TEXT = "encryptText";
    public static final String LOCATION = "location";
    public static final String SPACE = " ";

    /**
     * Remove default constructor and make it not available to initialize.
     */
    private SecureVaultConstants() {
        throw new AssertionError("Trying to a instantiate a constant class");
    }
}
