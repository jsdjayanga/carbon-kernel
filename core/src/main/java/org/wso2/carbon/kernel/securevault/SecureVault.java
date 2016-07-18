package org.wso2.carbon.kernel.securevault;

/**
 * Created by jayanga on 7/18/16.
 */
public interface SecureVault {
    char[] resolve(String alias);
}
