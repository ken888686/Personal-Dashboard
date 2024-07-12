import { ApiProperty } from '@nestjs/swagger';
import { Base } from './base.dto';

export class SignUpDto extends Base {
  @ApiProperty({ type: String })
  displayName: string;

  @ApiProperty({ type: String, required: false })
  photoUrl?: string;

  @ApiProperty({ type: String, required: false })
  firstName?: string;

  @ApiProperty({ type: String, required: false })
  lastName?: string;
}
