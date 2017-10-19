package org.wso2.carbon.kernel.internal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.base.CarbonComponent;
import org.wso2.carbon.config.ConfigProviderFactory;
import org.wso2.carbon.config.provider.ConfigProvider;
import org.wso2.carbon.kernel.CarbonRuntime;
import org.wso2.carbon.kernel.internal.context.CarbonRuntimeFactory;
import org.wso2.carbon.kernel.internal.jmx.CarbonJMXComponent;
import org.wso2.carbon.utils.Constants;
import org.wso2.carbon.utils.Utils;

import java.nio.file.Path;
import java.nio.file.Paths;


/**
 * This service component creates a carbon runtime based on the carbon configuration file and registers it as a
 * ${@link CarbonRuntime}.
 *
 * @since 5.2.0
 */
public class CarbonCoreComponent implements CarbonComponent {
    private static final Logger logger = LoggerFactory.getLogger(CarbonCoreComponent.class);
    CarbonRuntime carbonRuntime;
    CarbonJMXComponent carbonJMXComponent;

    @Override
    public String getName() {
        return CarbonCoreComponent.class.getName();
    }

    @Override
    public boolean start() throws Exception {
        try {
            logger.debug("Activating CarbonCoreComponent");

            Path deploymentConfigPath = Paths.get(Utils.getRuntimeConfigPath().toString(),
                    Constants.DEPLOYMENT_CONFIG_YAML);
            ConfigProvider configProvider = ConfigProviderFactory.getConfigProvider(deploymentConfigPath);

            // 2) Creates the CarbonRuntime instance using the Carbon configuration provider.
            carbonRuntime = CarbonRuntimeFactory.createCarbonRuntime(configProvider);

            carbonJMXComponent = new CarbonJMXComponent(carbonRuntime);
            carbonJMXComponent.start();


        } catch (Throwable throwable) {
            logger.error("Error while activating CarbonCoreComponent");
        }
        return true;
    }

    @Override
    public boolean stop() throws Exception {
        logger.debug("Deactivating CarbonCoreComponent");
        return true;
    }
}
