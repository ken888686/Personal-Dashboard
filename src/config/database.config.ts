import { ConfigService } from '@nestjs/config';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';

export const getDatabaseConfig = (configService: ConfigService): TypeOrmModuleOptions => ({
  type: 'postgres',
  // host: configService.get<string>('POSTGRES_HOST', 'localhost'),
  // port: configService.get<number>('POSTGRES_PORT', 5432),
  url: configService.get<string>('POSTGRES_URL'),
  username: configService.get<string>('POSTGRES_USER', 'donald'),
  password: configService.get<string>('POSTGRES_PASSWORD', 'donald'),
  database: configService.get<string>('POSTGRES_DATABASE', 'postgres'),
  entities: [__dirname + '/../**/*.entity{.ts,.js}'],
  synchronize: configService.get<boolean>('DATABASE_SYNCHRONIZE', false),
  logging: true,
});
