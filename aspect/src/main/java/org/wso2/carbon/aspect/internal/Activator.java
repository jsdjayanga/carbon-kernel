package org.wso2.carbon.aspect.internal;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Created by jayanga on 10/5/16.
 */
public class Activator implements BundleActivator {
    private static final Logger logger = LoggerFactory.getLogger(Activator.class);

    @Override
    public void start(BundleContext bundleContext) throws Exception {
        logger.info("==============Activating Aspects Activator");
    }

    @Override
    public void stop(BundleContext bundleContext) throws Exception {
        logger.info("==============Deactivating Aspects Activator");
    }
}
