import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

class Demo {
    private static final Logger LOG = LogManager.getLogger(Demo.class);
    void bad(String ua) {
        // ruleid: driftguard.java.log4j-nonconstant-log-message
        LOG.info("ua {}", ua);
    }
    void good() {
        // ok: driftguard.java.log4j-nonconstant-log-message
        LOG.info("started");
    }
}
