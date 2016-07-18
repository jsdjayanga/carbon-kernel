package org.wso2.carbon.kernel.securevault;


import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.util.List;

/**
 * Created by jayanga on 7/13/16.
 */
public interface SecretProvider {
    void provide(List<Secret> secrets) throws SecureVaultException;
}
