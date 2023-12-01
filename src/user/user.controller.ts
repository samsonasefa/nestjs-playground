import { Controller, Get, UseGuards } from '@nestjs/common';
import { User } from 'prisma/prisma-client';
import { GetUser } from 'src/auth/decorator';
import { JwtGuard } from 'src/auth/guard';

@Controller('user')
export class UserController {
  @UseGuards(JwtGuard)
  @Get('me')
  getme(@GetUser() user: User) {
    return user;
  }
}
