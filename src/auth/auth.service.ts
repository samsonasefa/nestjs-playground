import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import * as argon from 'argon2';
import { error } from 'console';
import { PrismaService } from 'src/prisma/prisma.service';

import { AuthDto } from './dto';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signup(dto: AuthDto) {
    // generate password hash
    try {
      const hash = await argon.hash(dto.password);

      // save the new user
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      // return the saved user with out hash

      delete user.hash;

      return user;
    } catch (error) {
      console.log({ error });
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
    }
    throw error;
  }

  async signin(dto: AuthDto) {
    // find the user
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    // if user does exist throw excepetion
    if (!user) {
      throw new ForbiddenException('Credentials incorrect');
    }

    // compare password
    const passwordMatch = await argon.verify(user.hash, dto.password);

    // if password is incorrect throw exception
    if (!passwordMatch) {
      throw new ForbiddenException('Credentials incorrect');
    }

    delete user.hash;

    // send the user
    return user;
  }
}
