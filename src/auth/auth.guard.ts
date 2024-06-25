import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { AuthProvider } from './dtos/auth.enum';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly authService: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const token: string = request.headers.authorization;
    if (!token) {
      throw new UnauthorizedException('Missing authorization token');
    }

    try {
      const authProvider = await this.authService.determineAuthProvider(token);
      if (authProvider === AuthProvider.GOOGLE) {
        const result = await this.authService.verifyGoogleToken(token);
        console.log(AuthProvider.GOOGLE, result);
      } else {
        const result = await this.authService.verifyToken(token);
        console.log(AuthProvider.FIREBASE, result);
      }
      return true;
    } catch (error) {
      console.error('Error verifying token:', error);
      throw new UnauthorizedException('Invalid token');
    }
  }
}
