import { Body, Controller, Get, HttpCode, HttpStatus, Put, Query } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UserService } from './user.service';

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @HttpCode(HttpStatus.OK)
  @Get()
  async getByEmail(@Query('email') email: string) {
    return await this.userService.findOneByEmail(email);
  }

  @HttpCode(HttpStatus.CREATED)
  @Put()
  async create(@Body() createUserDto: CreateUserDto) {
    await this.userService.upsert(createUserDto);
  }
}
