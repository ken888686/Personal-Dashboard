export class CreateUserDto {
  email: string;
  emailVerified: boolean;
  displayName: string;
  photoUrl?: string;
  firstName?: string;
  lastName?: string;
}
