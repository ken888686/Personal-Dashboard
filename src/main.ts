import { Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: ['log', 'fatal', 'error', 'warn', 'debug', 'verbose'],
  });

  const configService = app.get<ConfigService>(ConfigService);

  const globalPrefix = configService.get<string>('PREFIX') || 'api';
  const port = configService.get<number>('PORT') || 3001;
  app.setGlobalPrefix(globalPrefix);

  // CORS
  app.enableCors();

  await app.listen(port);
  Logger.log(`🚀 Application is running on: http://localhost:${port}/${globalPrefix}`);
}
bootstrap();
