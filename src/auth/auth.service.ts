import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as admin from 'firebase-admin';
import { DecodedIdToken } from 'firebase-admin/lib/auth/token-verifier';
import { FirebaseApp, getApps, initializeApp } from 'firebase/app';
import {
  Auth,
  createUserWithEmailAndPassword,
  getAuth,
  signInWithEmailAndPassword,
} from 'firebase/auth';
import { OAuth2Client } from 'google-auth-library';
import { google } from 'googleapis';
import { TokenDto } from './dtos/auth.dto';
import { AuthProvider } from './dtos/auth.enum';

@Injectable()
export class AuthService {
  private readonly firebaseAuth: Auth;
  private readonly firebaseApp: FirebaseApp;
  private readonly firebaseAdmin: admin.app.App;
  private readonly oauth2Client: OAuth2Client;

  constructor(private readonly configService: ConfigService) {
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

  async login(username: string, pass: string): Promise<TokenDto> {
    try {
      const { user } = await signInWithEmailAndPassword(this.firebaseAuth, username, pass);
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

  async signUp(username: string, pass: string): Promise<TokenDto> {
    try {
      const { user } = await createUserWithEmailAndPassword(this.firebaseAuth, username, pass);
      if (!user) {
        throw new UnauthorizedException();
      }

      //TODO: Save user to db

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

    //TODO: Save user to db

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
      name: payload['name'],
      picture: payload['picture'],
    };
  }
}
