import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {
  @ApiProperty({ type: String })
  email: string;

  @ApiProperty({ type: Boolean })
  emailVerified: boolean;

  @ApiProperty({ type: String })
  displayName: string;

  @ApiProperty({ type: String })
  loginType: string;

  @ApiProperty({ type: String, required: false })
  photoUrl?: string;

  @ApiProperty({ type: String, required: false })
  firstName?: string;

  @ApiProperty({ type: String, required: false })
  lastName?: string;
}
