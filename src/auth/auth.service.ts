import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { FirebaseApp, initializeApp } from 'firebase/app';
import {
  Auth,
  createUserWithEmailAndPassword,
  getAuth,
  signInWithEmailAndPassword,
} from 'firebase/auth';

@Injectable()
export class AuthService {
  private readonly firebaseAuth: Auth;
  private readonly firebaseApp: FirebaseApp;

  constructor(private readonly configService: ConfigService) {
    this.firebaseApp = initializeApp({
      apiKey: this.configService.get<string>('API_KEY'),
      authDomain: this.configService.get<string>('AUTH_DOMAIN'),
      projectId: this.configService.get<string>('PROJECT_ID'),
      storageBucket: this.configService.get<string>('STORAGE_BUCKET'),
      messagingSenderId: this.configService.get<string>('MESSAGING_SENDER_ID'),
      appId: this.configService.get<string>('APP_ID'),
      measurementId: this.configService.get<string>('MEASUREMENT_ID'),
    });
    this.firebaseAuth = getAuth(this.firebaseApp);
  }

  async login(username: string, pass: string): Promise<any> {
    try {
      const { user } = await signInWithEmailAndPassword(
        this.firebaseAuth,
        username,
        pass,
      );
      if (!user) {
        throw new UnauthorizedException();
      }

      return {
        token: await user.getIdToken(true),
        refreshToken: user.refreshToken,
      };
    } catch (error) {
      throw new UnauthorizedException(error);
    }
  }

  async signUp(username: string, pass: string): Promise<any> {
    try {
      const { user } = await createUserWithEmailAndPassword(
        this.firebaseAuth,
        username,
        pass,
      );
      if (!user) {
        throw new UnauthorizedException();
      }

      return {
        token: await user.getIdToken(true),
        refreshToken: user.refreshToken,
      };
    } catch (error) {
      console.log(error);
      throw new UnauthorizedException();
    }
  }
}
