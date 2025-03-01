import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UsersRepository } from './users.repository';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { JwtPayload } from './jwt-payload.interface';
import { User } from './user.entity';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  private usersRepository: UsersRepository;

  // constructor(
  //   @InjectRepository(UsersRepository)
  //   private usersRepository: UsersRepository,
  // ) {
  //   super({
  //     secretOrKey: 'topSecret51',
  //     jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  //   });
  // }
  constructor(
    @InjectDataSource()
    private dataSource: DataSource,
  ) {
    super({
      secretOrKey: 'topSecret51',
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    });
    this.usersRepository = new UsersRepository(this.dataSource);
  }

  async validate(payload: JwtPayload): Promise<User> {
    const user: User = await this.usersRepository.findOne({
      where: { username: payload.username },
    });

    if (!user) {
      throw new UnauthorizedException();
    }

    return user;
  }
}
