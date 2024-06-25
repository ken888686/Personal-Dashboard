import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './entity/user.entity';

@Injectable()
export class UserService {
  private readonly logger = new Logger(UserService.name);

  constructor(@InjectRepository(User) private usersRepository: Repository<User>) {}

  async existsByEmail(email: string): Promise<boolean> {
    this.logger.log(`check email exists: ${email}`);
    return await this.usersRepository.existsBy({ email: email });
  }

  async findOneByEmail(email: string): Promise<User> {
    this.logger.log(`find user by email: ${email}`);
    return await this.usersRepository.findOneBy({ email: email });
  }

  async upsert(newUser: CreateUserDto): Promise<User> {
    this.logger.log(`upsert user: ${JSON.stringify(newUser)}`);
    return await this.usersRepository.save(newUser);
  }
}
