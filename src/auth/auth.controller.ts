import { Body, Controller, Get, HttpCode, HttpStatus, Post, Req } from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { LoginDto, SignUpDto, TokenDto } from './dtos/auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(@Body() loginRequest: LoginDto): Promise<TokenDto> {
    return await this.authService.login(loginRequest.email, loginRequest.password);
  }

  @HttpCode(HttpStatus.OK)
  @Post('signup')
  async signUp(@Body() signRequest: SignUpDto): Promise<TokenDto> {
    return await this.authService.signUp(signRequest.email, signRequest.password);
  }

  @Get('google/login')
  handlerLogin(): string {
    return this.authService.handlerLogin();
  }

  @Get('google/redirect')
  async handlerRedirect(@Req() request: Request): Promise<TokenDto> {
    const query = request.query;
    const tokens = await this.authService.handlerRedirect(query['code'] as string);
    return {
      access_token: tokens.id_token,
      refresh_token: tokens.refresh_token,
    };
  }
}
