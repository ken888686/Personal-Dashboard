import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
  @Post('login')
  async login(
    @Body() loginDto: { email: string; password: string },
  ): Promise<any> {
    return await this.authService.login(loginDto.email, loginDto.password);
  }

  @HttpCode(HttpStatus.OK)
  @Post('signup')
  async signUp(
    @Body() signDto: { email: string; password: string },
  ): Promise<any> {
    return await this.authService.signUp(signDto.email, signDto.password);
  }
}
