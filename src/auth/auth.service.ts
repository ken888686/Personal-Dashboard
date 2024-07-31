import { BadRequestException, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import * as admin from 'firebase-admin';
import { DecodedIdToken } from 'firebase-admin/lib/auth/token-verifier';
import { FirebaseApp, getApps, initializeApp } from 'firebase/app';
import {
  Auth,
  createUserWithEmailAndPassword,
  getAuth,
  signInWithEmailAndPassword,
  updateProfile,
} from 'firebase/auth';
import { OAuth2Client } from 'google-auth-library';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { User } from 'src/user/entity/user.entity';
import { UserService } from 'src/user/user.service';
import { AuthProvider } from './dtos/auth.enum';
import { SignUpDto } from './dtos/sign-up.dto';
import { TokenDto } from './dtos/token.dto';

@Injectable()
export class AuthService {
  private readonly firebaseAuth: Auth;
  private readonly firebaseApp: FirebaseApp;
  private readonly firebaseAdmin: admin.app.App;
  private readonly oauth2Client: OAuth2Client;
  private readonly logger: Logger;

  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    private jwtService: JwtService,
  ) {
    this.logger = new Logger(AuthService.name);

    this.firebaseApp =
      getApps()[0] ||
      initializeApp({
        apiKey: this.configService.get<string>('API_KEY'),
        authDomain: this.configService.get<string>('AUTH_DOMAIN'),
        projectId: this.configService.get<string>('PROJECT_ID'),
        storageBucket: this.configService.get<string>('STORAGE_BUCKET'),
        messagingSenderId: this.configService.get<string>('MESSAGING_SENDER_ID'),
        appId: this.configService.get<string>('APP_ID'),
      });
    this.firebaseAuth = getAuth(this.firebaseApp);

    const projectId = this.configService.get<string>('PROJECT_ID');
    const clientEmail = this.configService.get<string>('CLIENT_EMAIL');
    const privateKey = this.configService.get<string>('PRIVATE_KEY');
    this.firebaseAdmin =
      admin.apps[0] ||
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId,
          clientEmail,
          privateKey: privateKey.replace(/\\n/g, '\n'),
        }),
      });

    this.oauth2Client = new OAuth2Client(
      this.configService.get<string>('CLIENT_ID'),
      this.configService.get<string>('CLIENT_SECRET'),
      this.configService.get<string>('CALLBACK_URL'),
    );
  }

  async loginWithPassword(email: string, password: string): Promise<TokenDto> {
    try {
      this.logger.log(`check email exists: ${email}`);
      const exists = await this.userService.existsByEmail(email);
      if (!exists) {
        const msg = `${email} doesn't exist`;
        this.logger.error(msg);
        throw new NotFoundException(msg);
      }

      this.logger.log('login with email');
      const { user } = await signInWithEmailAndPassword(this.firebaseAuth, email, password);
      if (!user) {
        const msg = 'User not found';
        this.logger.error(msg);
        throw new BadRequestException(msg);
      }

      this.logger.log('get user id token');
      const result = await user.getIdTokenResult();

      this.logger.log('get user information from db');
      const userInfo = await this.userService.findOneByEmail(user.email);

      this.logger.log('generate jwt payload');
      const payload = {
        id: userInfo.id,
        loginType: AuthProvider.PASSWORD,
        email: user.email,
        emailVerified: user.emailVerified,
        displayName: userInfo.displayName,
        photoUrl: userInfo.photoUrl,
        firstName: userInfo.firstName,
        lastName: userInfo.lastName,
        providerId: result.signInProvider,
      };

      this.logger.log('sign access token');
      const accessToken = await this.jwtService.signAsync(payload);

      return {
        access_token: accessToken,
        refresh_token: user.refreshToken,
      };
    } catch (error) {
      this.logger.error(error);
      throw new BadRequestException(error);
    }
  }

  async signUpWithPassword(signUpDto: SignUpDto): Promise<TokenDto> {
    try {
      // Check email exists
      const exists = await this.userService.existsByEmail(signUpDto.email);
      if (exists) {
        const msg = `${signUpDto.email} already exists`;
        this.logger.error(msg);
        throw new BadRequestException(msg);
      }

      // Check password
      if (!this.verifyPassword(signUpDto.password)) {
        const msg =
          'Password is too weak. It must contain at least one lowercase letter, one uppercase letter, one digit, one special character, and be at least 8 characters long.';
        this.logger.warn(msg);
        throw new BadRequestException(msg);
      }

      const { user } = await createUserWithEmailAndPassword(
        this.firebaseAuth,
        signUpDto.email,
        signUpDto.password,
      );
      if (!user) {
        throw new BadRequestException();
      }

      // Add new user to pg
      const newUser: CreateUserDto = {
        email: user.email,
        emailVerified: user.emailVerified,
        displayName: signUpDto.displayName,
        photoUrl: signUpDto.photoUrl,
        loginType: AuthProvider.PASSWORD,
      };
      this.logger.log('create new user to pg');
      this.userService.upsert(newUser);

      // Update user information to firebase
      this.logger.log('update user profile to firebase');
      await updateProfile(this.firebaseAuth.currentUser, {
        displayName: signUpDto.displayName,
        photoURL: signUpDto.photoUrl,
      });

      return {
        access_token: await user.getIdToken(true),
        refresh_token: user.refreshToken,
      };
    } catch (error) {
      this.logger.error(error);
      throw new BadRequestException(error);
    }
  }

  private verifyPassword(password: string): boolean {
    // Regular expressions for each condition
    const lowerCaseRegex = /[a-z]/;
    const upperCaseRegex = /[A-Z]/;
    const digitRegex = /[0-9]/;
    const specialCharRegex = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/;

    // Check all conditions
    const hasLowerCase = lowerCaseRegex.test(password);
    const hasUpperCase = upperCaseRegex.test(password);
    const hasDigit = digitRegex.test(password);
    const hasSpecialChar = specialCharRegex.test(password);
    const hasMinLength = password.length >= 8;

    return hasLowerCase && hasUpperCase && hasDigit && hasSpecialChar && hasMinLength;
  }

  async getGoogleAuthURL() {
    try {
      this.logger.log('start generating url');
      const url = this.oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: ['email', 'profile'],
        include_granted_scopes: true,
        prompt: 'select_account',
      });
      this.logger.log('generated url success');
      return url;
    } catch (error) {
      this.logger.error(error);
      throw new BadRequestException(error);
    }
  }

  async googleAuthCallback(request: Request): Promise<TokenDto> {
    try {
      this.logger.log('get code from query params');
      const { code } = request.query;

      this.logger.log('get tokens from query params');
      const { tokens } = await this.oauth2Client.getToken(code as string);

      this.oauth2Client.setCredentials(tokens);

      this.logger.log('verify token');
      const payload = await this.getGoogleOAuthPayload(tokens.id_token);

      this.logger.log('insert or update user profile to database');
      const newUser: CreateUserDto = {
        email: payload.email,
        emailVerified: payload.emailVerified,
        displayName: payload.displayName,
        loginType: AuthProvider.GOOGLE,
        photoUrl: payload.picture,
        firstName: payload.firstName,
        lastName: payload.lastName,
      };
      const user = await this.userService.upsert(newUser);
      const jwt = await this.generateTokens(user, AuthProvider.GOOGLE, tokens.refresh_token);

      return {
        access_token: jwt.accessToken,
        refresh_token: jwt.refreshToken,
      };
    } catch (error) {
      this.logger.error(error);
      throw new BadRequestException(error);
    }
  }

  async verifyToken(idToken: string): Promise<DecodedIdToken> {
    try {
      this.logger.log('verify token');
      const result = await this.jwtService.verifyAsync(idToken);
      return result;
    } catch (error) {
      this.logger.error(error);
      throw new BadRequestException(error);
    }
  }

  async getGoogleOAuthPayload(token: string) {
    try {
      this.logger.log('verify google token');
      const ticket = await this.oauth2Client.verifyIdToken({
        idToken: token,
        audience: this.configService.get<string>('CLIENT_ID'),
      });

      this.logger.log('get payload from google token');
      const payload = ticket.getPayload();
      return {
        uid: payload.sub,
        email: payload.email,
        emailVerified: payload.email_verified,
        displayName: payload.name,
        lastName: payload.given_name,
        firstName: payload.family_name,
        picture: payload.picture,
        aud: payload.aud,
      };
    } catch (error) {
      this.logger.error(error);
      throw new BadRequestException(error);
    }
  }

  private async generateTokens(userInfo: User, provider: string, refreshToken: string) {
    const accessToken = await this.jwtService.signAsync(
      { ...userInfo, provider },
      {
        secret: this.configService.get<string>('JWT_SECRET'),
        expiresIn: '1d',
      },
    );

    return {
      accessToken,
      refreshToken,
    };
  }
}
