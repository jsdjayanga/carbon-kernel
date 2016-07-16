package org.wso2.carbon.kernel.securevault.exception;

/**
 * Created by jayanga on 7/13/16.
 */
public class SecureVaultException extends Exception {
    public SecureVaultException(String message) {
        super(message);
    }

    public SecureVaultException(String message, Throwable cause) {
        super(message, cause);
    }
}
