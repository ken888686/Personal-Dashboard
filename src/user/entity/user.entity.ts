import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity({ name: 'user', comment: 'User information' })
export class User {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: number;

  @Column({ name: 'display_name', type: 'varchar', length: 255, nullable: true })
  displayName: string;

  @Column({ name: 'first_name', type: 'varchar', length: 255, nullable: true })
  firstName: string;

  @Column({ name: 'last_name', type: 'varchar', length: 255, nullable: true })
  lastName: string;

  @Column({ type: 'varchar', length: 255, unique: true })
  email: string;

  @Column({ name: 'photo_url', type: 'varchar', length: 255, nullable: true })
  photoUrl: string;

  @Column({ name: 'email_verified', type: 'boolean', default: false })
  emailVerified: boolean = false;

  @Column({ type: 'boolean', default: true })
  enabled: boolean = true;

  @Column({ type: 'varchar', length: 255, default: '' })
  loginType: string;

  @Column({ name: 'create_at', type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  createAt: Date;

  @Column({ name: 'update_at', type: 'timestamptz', default: () => 'CURRENT_TIMESTAMP' })
  updateAt: Date;
}
