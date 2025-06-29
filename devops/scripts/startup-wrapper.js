#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const winston = require('winston');
const prometheus = require('prom-client');

// Configure Winston logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    defaultMeta: { service: 'tradesage-app' },
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' })
    ]
});

// Configure Prometheus metrics
const register = new prometheus.Registry();
const startupErrors = new prometheus.Counter({
    name: 'node_startup_errors_total',
    help: 'Total number of startup errors',
    labelNames: ['error_type']
});
const cwdValidationErrors = new prometheus.Counter({
    name: 'node_cwd_validation_errors_total',
    help: 'Total number of CWD validation errors',
    labelNames: ['error_type']
});
register.registerMetric(startupErrors);
register.registerMetric(cwdValidationErrors);

// Default application directory (align with Docker WORKDIR)
const DEFAULT_APP_DIR = '/app';
const PROJECT_ROOT = path.resolve(__dirname, '../..');

/**
 * Validates the current working directory
 * @returns {Promise<boolean>}
 */
async function validateCWD() {
    try {
        // Get current working directory
        const cwd = process.cwd();
        logger.info('Current working directory check', { cwd });

        // Check if directory exists and is accessible
        await fs.promises.access(cwd, fs.constants.R_OK | fs.constants.W_OK);

        // Check for package.json to validate we're in a Node.js project directory
        const packageJsonPath = path.join(cwd, 'package.json');
        await fs.promises.access(packageJsonPath, fs.constants.R_OK);

        logger.info('CWD validation successful', { cwd });
        return true;
    } catch (error) {
        logger.error('CWD validation failed', { 
            error: error.message,
            code: error.code,
            stack: error.stack
        });
        cwdValidationErrors.inc({ error_type: error.code || 'UNKNOWN' });
        return false;
    }
}

/**
 * Sets up a safe working directory
 * @returns {Promise<string>} The resolved working directory
 */
async function setupSafeWorkingDirectory() {
    const candidateDirs = [
        process.cwd(),
        PROJECT_ROOT,
        DEFAULT_APP_DIR,
        '/tmp/app',
        path.resolve(require('os').homedir(), 'tradesage')
    ];

    for (const dir of candidateDirs) {
        try {
            // Check if directory exists
            if (!fs.existsSync(dir)) {
                await fs.promises.mkdir(dir, { recursive: true });
            }

            // Verify directory permissions
            await fs.promises.access(dir, fs.constants.R_OK | fs.constants.W_OK);

            // Try to set as current working directory
            process.chdir(dir);
            logger.info('Successfully set working directory', { dir });
            return dir;
        } catch (error) {
            logger.warn('Failed to set working directory', { 
                dir,
                error: error.message
            });
            continue;
        }
    }

    throw new Error('Failed to set up a safe working directory');
}

/**
 * Main startup function
 */
async function startup() {
    try {
        logger.info('Starting application initialization');

        // Validate current working directory
        const isValidCWD = await validateCWD();
        
        if (!isValidCWD) {
            logger.warn('Invalid CWD detected, attempting to set up safe directory');
            const safeDir = await setupSafeWorkingDirectory();
            logger.info('Safe working directory established', { directory: safeDir });
        }

        // Export metrics for monitoring
        const metrics = await register.metrics();
        await fs.promises.writeFile(
            path.join(process.cwd(), 'startup-metrics.prom'),
            metrics
        );

        // Continue with the actual application startup
        logger.info('Environment validation complete, proceeding with application startup');
        
        // Hand over to the actual application
        require(path.join(process.cwd(), process.argv[2] || 'index.js'));
    } catch (error) {
        logger.error('Fatal error during startup', {
            error: error.message,
            stack: error.stack
        });
        startupErrors.inc({ error_type: error.code || 'UNKNOWN' });
        process.exit(1);
    }
}

// Start the application
startup().catch(error => {
    logger.error('Unhandled error during startup', {
        error: error.message,
        stack: error.stack
    });
    process.exit(1);
}); 