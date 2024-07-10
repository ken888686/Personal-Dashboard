import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { AuthGuard } from './auth.guard';
import { AuthService } from './auth.service';
import { AuthProvider } from './dtos/auth.enum';
import { LoginDto } from './dtos/login.dto';
import { SignUpDto } from './dtos/sign-up.dto';
import { TokenDto } from './dtos/token.dto';

@Controller('auth')
export class AuthController {
  private readonly logger: Logger;

  constructor(private readonly authService: AuthService) {
    this.logger = new Logger(AuthController.name);
  }

  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(@Body() loginDto: LoginDto): Promise<TokenDto> {
    this.logger.log('email and password login');
    return await this.authService.login(loginDto.email, loginDto.password);
  }

  @HttpCode(HttpStatus.CREATED)
  @Post('signup')
  async signUp(@Body() signUpDto: SignUpDto): Promise<TokenDto> {
    this.logger.log('email and password signup');
    return await this.authService.signUp(signUpDto);
  }

  @Get('google')
  handlerLogin(): string {
    this.logger.log('handle google login');
    return this.authService.handlerLogin();
  }

  @Get('google/redirect')
  async handlerRedirect(@Req() request: Request): Promise<TokenDto> {
    this.logger.log('handle google login redirect');
    const query = request.query;
    const tokens = await this.authService.handlerRedirect(query['code'] as string);
    return {
      access_token: tokens.id_token,
      refresh_token: tokens.refresh_token,
    };
  }

  @Get('profile')
  @UseGuards(AuthGuard)
  async test(@Req() request: Request): Promise<any> {
    const token = request.headers.authorization;
    const provider = await this.authService.determineAuthProvider(token);
    switch (provider) {
      case AuthProvider.FIREBASE: {
        const user = await this.authService.verifyToken(token);
        return {
          provider,
          user,
        };
      }
      case AuthProvider.GOOGLE: {
        const user = await this.authService.verifyGoogleToken(token);
        return {
          provider,
          user,
        };
      }
      default:
        return null;
    }
  }
}
