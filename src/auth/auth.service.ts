import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
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

  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
  ) {
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
      const exists = await this.userService.existsByEmail(email);
      if (!exists) {
        throw new NotFoundException(`${email} doesn't exist`);
      }

      const { user } = await signInWithEmailAndPassword(this.firebaseAuth, email, password);
      if (!user) {
        throw new UnauthorizedException();
      }

      return {
        access_token: await user.getIdToken(true),
        refresh_token: user.refreshToken,
      };
    } catch (error) {
      throw new UnauthorizedException(error);
    }
  }

  async signUp(signUpDto: SignUpDto): Promise<TokenDto> {
    try {
      const { user } = await createUserWithEmailAndPassword(
        this.firebaseAuth,
        signUpDto.email,
        signUpDto.password,
      );
      if (!user) {
        throw new UnauthorizedException();
      }

      // Check email exists
      const exists = await this.userService.existsByEmail(user.email);
      if (!exists) {
        // Add new user to pg
        const newUser: CreateUserDto = {
          email: user.email,
          emailVerified: user.emailVerified,
          displayName: signUpDto.displayName,
          photoUrl: signUpDto.photoUrl,
        };
        this.userService.upsert(newUser);

        // Update user information to firebase
        await updateProfile(this.firebaseAuth.currentUser, {
          displayName: signUpDto.displayName,
          photoURL: signUpDto.photoUrl,
        });
      }

      return {
        access_token: await user.getIdToken(true),
        refresh_token: user.refreshToken,
      };
    } catch (error) {
      console.log(error);
      throw new UnauthorizedException();
    }
  }

  handlerLogin() {
    const url = this.oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: [
        // https://developers.google.com/identity/protocols/oauth2/scopes
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
      ],
      include_granted_scopes: true,
      prompt: 'consent',
    });
    return url;
  }

  async handlerRedirect(code: string) {
    const { tokens } = await this.oauth2Client.getToken(code);
    this.oauth2Client.setCredentials(tokens);

    const decodedIdToken = await this.verifyGoogleToken(tokens.id_token);

    // Check email exists
    const exists = await this.userService.existsByEmail(decodedIdToken.email);
    if (!exists) {
      // Add new user
      const newUser: CreateUserDto = {
        email: decodedIdToken.email,
        emailVerified: decodedIdToken.emailVerified,
        displayName: decodedIdToken.displayName,
        photoUrl: decodedIdToken.picture,
        firstName: decodedIdToken.firstName,
        lastName: decodedIdToken.lastName,
      };
      this.userService.upsert(newUser);
    }

    return tokens;
  }

  async determineAuthProvider(token: string) {
    try {
      await this.oauth2Client.verifyIdToken({
        idToken: token,
        audience: this.configService.get<string>('CLIENT_ID'),
      });
      return AuthProvider.GOOGLE;
    } catch (error) {
      return AuthProvider.FIREBASE;
    }
  }

  async verifyToken(idToken: string): Promise<DecodedIdToken> {
    const result = await this.firebaseAdmin.auth().verifyIdToken(idToken);
    return result;
  }

  async verifyGoogleToken(token: string) {
    const ticket = await this.oauth2Client.verifyIdToken({
      idToken: token,
      audience: this.configService.get<string>('CLIENT_ID'),
    });
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
  }
}
