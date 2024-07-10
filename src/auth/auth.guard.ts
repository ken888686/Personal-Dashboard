import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { AuthProvider } from './dtos/auth.enum';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger: Logger;
  constructor(private readonly authService: AuthService) {
    this.logger = new Logger(AuthGuard.name);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const token: string = request.headers.authorization;
    this.logger.log('get token from request header');
    if (!token) {
      throw new UnauthorizedException('Missing authorization token');
    }

    try {
      const authProvider = await this.authService.determineAuthProvider(token);
      if (authProvider === AuthProvider.GOOGLE) {
        await this.authService.verifyGoogleToken(token);
        this.logger.log(AuthProvider.GOOGLE);
      } else {
        await this.authService.verifyToken(token);
        this.logger.log(AuthProvider.FIREBASE);
      }
      return true;
    } catch (error) {
      this.logger.error('Error verifying token:', JSON.stringify(error));
      throw new UnauthorizedException('Invalid token');
    }
  }
}
