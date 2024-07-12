import { ApiProperty } from '@nestjs/swagger';

export class Base {
  @ApiProperty({ type: String })
  email: string;

  @ApiProperty({ type: String })
  password: string;
}
