import {
  BadRequestException,
  Injectable,
  Logger,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
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
import { google } from 'googleapis';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
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
        measurementId: this.configService.get<string>('MEASUREMENT_ID'),
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
    this.oauth2Client = new google.auth.OAuth2(
      this.configService.get<string>('CLIENT_ID'),
      this.configService.get<string>('CLIENT_SECRET'),
      this.configService.get<string>('CALLBACK_URL'),
    );
  }

  async login(email: string, password: string): Promise<TokenDto> {
    try {
      this.logger.log('check email exists:', email);
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
        throw new UnauthorizedException(msg);
      }

      return {
        access_token: await user.getIdToken(true),
        refresh_token: user.refreshToken,
      };
    } catch (error) {
      this.logger.error(error);
      throw new UnauthorizedException(error);
    }
  }

  async signUp(signUpDto: SignUpDto): Promise<TokenDto> {
    try {
      // Check email exists
      const exists = await this.userService.existsByEmail(signUpDto.email);
      if (exists) {
        const msg = `${signUpDto.email} already exists`;
        this.logger.error(msg);
        throw new BadRequestException(msg);
      }

      // Check password
      if (this.verifyPassword(signUpDto.password)) {
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

  handlerLogin() {
    try {
      this.logger.log('generate url');
      const url = this.oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: [
          // https://developers.google.com/identity/protocols/oauth2/scopes
          'email',
          'profile',
        ],
        include_granted_scopes: true,
        prompt: 'consent',
      });
      this.logger.log('generated url success');
      return url;
    } catch (error) {
      this.logger.error(error);
      throw new UnauthorizedException(error);
    }
  }

  async handlerRedirect(code: string) {
    try {
      this.logger.log('get token');
      const { tokens } = await this.oauth2Client.getToken(code);
      this.oauth2Client.setCredentials(tokens);

      this.logger.log('verify token');
      const decodedIdToken = await this.verifyGoogleToken(tokens.id_token);

      this.logger.log('insert or update user profile to pg');
      const newUser: CreateUserDto = {
        email: decodedIdToken.email,
        emailVerified: decodedIdToken.emailVerified,
        displayName: decodedIdToken.displayName,
        photoUrl: decodedIdToken.picture,
        firstName: decodedIdToken.firstName,
        lastName: decodedIdToken.lastName,
      };
      await this.userService.upsert(newUser);

      return tokens;
    } catch (error) {
      this.logger.error(error);
      throw new UnauthorizedException(error);
    }
  }

  async determineAuthProvider(token: string) {
    try {
      await this.oauth2Client.verifyIdToken({
        idToken: token,
        audience: this.configService.get<string>('CLIENT_ID'),
      });
      this.logger.log('google token');
      return AuthProvider.GOOGLE;
    } catch (error) {
      this.logger.log('firebase token');
      return AuthProvider.FIREBASE;
    }
  }

  async verifyToken(idToken: string): Promise<DecodedIdToken> {
    try {
      this.logger.log('verify email token');
      const result = await this.firebaseAdmin.auth().verifyIdToken(idToken);
      return result;
    } catch (error) {
      this.logger.error(error);
      throw new UnauthorizedException(error);
    }
  }

  async verifyGoogleToken(token: string) {
    try {
      this.logger.log('verify google token');
      const ticket = await this.oauth2Client.verifyIdToken({
        idToken: token,
        audience: this.configService.get<string>('CLIENT_ID'),
      });

      this.logger.log('get payload from google token');
      const payload = ticket.getPayload();
      return {
        uid: payload['sub'],
        email: payload['email'],
        emailVerified: payload['email_verified'],
        displayName: payload['name'],
        lastName: payload['given_name'],
        firstName: payload['family_name'],
        picture: payload['picture'],
      };
    } catch (error) {
      this.logger.error(error);
      throw new UnauthorizedException(error);
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
}
