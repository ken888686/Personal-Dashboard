export class CreateUserDto {
  email: string;
  emailVerified: boolean;
  displayName: string;
  loginType: string;
  photoUrl?: string;
  firstName?: string;
  lastName?: string;
}
