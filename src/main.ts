import { HttpException, HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // CORS
  app.enableCors({
    origin: '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    preflightContinue: false,
    optionsSuccessStatus: 204,
  });

  const configService = app.get<ConfigService>(ConfigService);
  const port = configService.get<number>('PORT');
  if (!port) {
    throw new HttpException('PORT is not set', HttpStatus.INTERNAL_SERVER_ERROR);
  }
  await app.listen(port || 3000);
}
bootstrap();
