/**
 * Validates configuration object (from load + env).
 * Ensures required values are present; throws at bootstrap if invalid.
 */
export function validate(config: Record<string, unknown>): Record<string, unknown> {
  const nodeEnv = config['nodeEnv'] as string | undefined;
  const port = config['port'];
  if (port != null && (typeof port !== 'number' || port < 1)) {
    throw new Error('Environment validation failed: PORT must be a positive number');
  }
  if (nodeEnv && !['development', 'production', 'test'].includes(nodeEnv)) {
    throw new Error(
      'Environment validation failed: NODE_ENV must be development, production, or test',
    );
  }
  const db = config['database'] as Record<string, unknown> | undefined;
  if (db) {
    if (typeof db['uri'] !== 'string' || !db['uri']) {
      throw new Error('Environment validation failed: database.uri (MONGODB_URI) is required');
    }
  }
  const jwt = config['jwt'] as Record<string, unknown> | undefined;
  if (jwt) {
    if (typeof jwt['accessSecret'] !== 'string' || !jwt['accessSecret']) {
      throw new Error('Environment validation failed: jwt.accessSecret is required');
    }
    if (typeof jwt['refreshSecret'] !== 'string' || !jwt['refreshSecret']) {
      throw new Error('Environment validation failed: jwt.refreshSecret is required');
    }
  }
  return config;
}
