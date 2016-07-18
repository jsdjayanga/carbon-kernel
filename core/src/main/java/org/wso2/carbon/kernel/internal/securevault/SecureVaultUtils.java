package org.wso2.carbon.kernel.internal.securevault;

import org.osgi.framework.BundleContext;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.kernel.securevault.Secret;
import org.wso2.carbon.kernel.securevault.exception.SecureVaultException;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Created by jayanga on 7/13/16.
 */
public class SecureVaultUtils {
    private static final Logger logger = LoggerFactory.getLogger(SecureVaultUtils.class);

    public static ServiceReference getServiceReference(BundleContext bundleContext, String propertyName,
                                                       String serviceClassName, String serviceName)
            throws SecureVaultException {
        ServiceReference[] serviceReferences;
        try {
            serviceReferences = bundleContext.getServiceReferences(serviceClassName, null);
        } catch (InvalidSyntaxException e) {
            throw new SecureVaultException("Error while retrieving OSGi service reference");
        }

        for (ServiceReference serviceReference : serviceReferences) {
            if (serviceName.equals(serviceReference.getProperty(propertyName))) {
                logger.info("Service provider '{}' found with given property '{}'", serviceName, propertyName);
                return serviceReference;
            }
        }

        throw new SecureVaultException("Unable to find an implementation for '" + serviceName
                + "' with property '" + propertyName + "'");
    }

    public static List<Secret> createSecrets(List<String> paramaters) {
        List<Secret> secrets = new ArrayList<>();
        for (String paramater : paramaters) {
            secrets.add(new Secret(paramater));
        }
        return secrets;
    }

    public static Secret getSecret(List<Secret> secrets, String secretName) throws SecureVaultException {
        for (Secret secret : secrets) {
            if (secret.getSecretName().equals(secretName)) {
                return secret;
            }
        }
        throw new SecureVaultException("No secret found with given secret name '" + secretName + "'");
    }

    public static byte[] base64Decode(String base64Encoded) {
        byte[] decodedValue = Base64.getDecoder().decode(base64Encoded);
        return decodedValue;
    }

    public static char[] toChars(byte[] bytes) {
        Charset charset = Charset.forName("UTF-8");
        return charset.decode(ByteBuffer.wrap(bytes)).array();
    }
}
