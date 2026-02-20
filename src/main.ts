import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { AppLoggerService } from './common/logger/logger.service';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule);
  const config = app.get(ConfigService);
  const logger = app.get(AppLoggerService);

  const apiPrefix = config.get<string>('apiPrefix');
  const apiVersion = config.get<string>('apiVersion');
  app.setGlobalPrefix(`${apiPrefix}/${apiVersion}`);

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: { enableImplicitConversion: true },
    }),
  );

  app.use(
    helmet({
      contentSecurityPolicy: config.get<string>('nodeEnv') === 'production',
    }),
  );

  const corsOrigin = config.get<string>('cors.origin') ?? '*';
  const corsCredentials = config.get<boolean>('cors.credentials') ?? false;
  app.enableCors({
    origin: corsOrigin === '*' ? true : corsOrigin.split(',').map((o) => o.trim()),
    credentials: corsCredentials,
  });

  if (config.get<boolean>('swagger.enabled')) {
    const swaggerPath = config.get<string>('swagger.path') ?? 'api/docs';
    const doc = new DocumentBuilder()
      .setTitle('Auth Microservice API')
      .setDescription('Production-ready authentication API with JWT, refresh rotation, and RBAC')
      .setVersion('1.0')
      .addBearerAuth()
      .build();
    const document = SwaggerModule.createDocument(app, doc);
    SwaggerModule.setup(swaggerPath, app, document);
  }

  const port = config.get<number>('port') ?? 3000;
  await app.listen(port);

  app.enableShutdownHooks();

  process.on('SIGTERM', async () => {
    logger.log('SIGTERM received, shutting down gracefully');
    await app.close();
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    logger.log('SIGINT received, shutting down gracefully');
    await app.close();
    process.exit(0);
  });

  logger.log(`Application listening on port ${port}`);
}

bootstrap().catch((err) => {
  console.error('Bootstrap failed', err);
  process.exit(1);
});
