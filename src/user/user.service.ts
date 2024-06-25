import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './entity/user.entity';

@Injectable()
export class UserService {
  constructor(@InjectRepository(User) private usersRepository: Repository<User>) {}

  async existsByEmail(email: string): Promise<boolean> {
    return await this.usersRepository.existsBy({ email: email });
  }

  async findOneByEmail(email: string): Promise<User> {
    return await this.usersRepository.findOneBy({ email: email });
  }

  async upsert(newUser: CreateUserDto): Promise<User> {
    return await this.usersRepository.save(newUser);
  }
}
