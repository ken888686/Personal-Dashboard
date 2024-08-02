import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Logger,
  Post,
  Put,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiTags,
} from '@nestjs/swagger';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { LoginDto } from './dtos/login.dto';
import { SignUpDto } from './dtos/sign-up.dto';
import { TokenDto } from './dtos/token.dto';
import { JwtAuthGuard } from './jwt-auth.guard';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  private readonly logger: Logger;

  constructor(private readonly authService: AuthService) {
    this.logger = new Logger(AuthController.name);
  }

  @HttpCode(HttpStatus.OK)
  @Post('login')
  @ApiBody({ type: LoginDto })
  @ApiOkResponse({ type: TokenDto })
  async login(@Body() loginDto: LoginDto): Promise<TokenDto> {
    this.logger.log('email and password login');
    return await this.authService.loginWithPassword(loginDto.email, loginDto.password);
  }

  @HttpCode(HttpStatus.CREATED)
  @Post('signup')
  @ApiBody({ type: SignUpDto })
  @ApiCreatedResponse({ type: TokenDto })
  async signUp(@Body() signUpDto: SignUpDto): Promise<TokenDto> {
    this.logger.log('email and password signup');
    return await this.authService.signUpWithPassword(signUpDto);
  }

  @UseGuards(JwtAuthGuard)
  @Put('email/send-verification')
  @ApiBearerAuth()
  async sendVerification(@Req() request: Request): Promise<{
    message: string;
  }> {
    this.logger.log('handle email verify');
    const token = request.headers.authorization.split(' ')[1];
    const payload = await this.authService.verifyToken(token);
    return await this.authService.verifyEmail(payload['email']);
  }

  @Get('email/verify/callback')
  @ApiBearerAuth()
  verifyEmailCallback(): string {
    this.logger.log('handle email verify');
    return 'Please re-login your account again. You can close this window now.';
  }

  @Get('google')
  async googleAuth(@Res() res: Response) {
    try {
      this.logger.log('get google auth url');
      const url = await this.authService.getGoogleAuthURL();
      res.redirect(url);
    } catch (error) {
      this.logger.error(error);
      throw new UnauthorizedException('Invalid Google token');
    }
  }

  @Get('google/callback')
  async googleAuthCallback(@Req() request: Request): Promise<TokenDto> {
    this.logger.log('handle google login callback');
    const tokens = await this.authService.googleAuthCallback(request);
    return {
      access_token: tokens.access_token,
      refresh_token: tokens.refresh_token,
    };
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  @ApiBearerAuth()
  async profile(@Req() request: Request): Promise<any> {
    const token = request.headers.authorization.split(' ')[1];
    return {
      payload: await this.authService.verifyToken(token),
    };
  }
}
