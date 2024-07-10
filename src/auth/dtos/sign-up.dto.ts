import { Base } from './base.dto';

export interface SignUpDto extends Base {
  displayName: string;
  photoUrl?: string;
  firstName?: string;
  lastName?: string;
}
