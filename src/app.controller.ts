import { Controller, Get, Res } from '@nestjs/common';
import { ApiExcludeController } from '@nestjs/swagger';
import { Response } from 'express';
import { AppService } from './app.service';

@ApiExcludeController()
@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get('')
  redirectToSwagger(@Res() response: Response) {
    return response.redirect('/api/swagger');
  }
}
