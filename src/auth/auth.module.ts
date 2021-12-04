import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UserModule } from 'src/user/user.module';
import { JwtStrategy } from './jwt.strategy';
import { RolesGuard } from './guards/roles.guard';

@Module({
  imports: [UserModule],
  providers: [AuthService,JwtStrategy,RolesGuard],
  controllers: [AuthController]
})
export class AuthModule {}
