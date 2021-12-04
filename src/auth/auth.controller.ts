import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport/dist/auth.guard';
import { Role } from 'src/models/role.enum';
import { RegisterDTO } from 'src/user/dto/register.dto';
import { UserService } from 'src/user/user.service';
import { AuthService } from './auth.service';
import { Roles } from './decorators/roles.decorator';
import { LoginDTO } from './dto/login.dto';
import { RolesGuard } from './guards/roles.guard';

@Controller('auth')
export class AuthController {
    constructor(
        private userService: UserService,
        private authService: AuthService,       
      ) {}


    @Roles(Role.ADMIN)
    @UseGuards(AuthGuard("jwt"), RolesGuard)
    @Get("/onlyauth")
    async hiddenInformation(){
        return  "hidden information";
    }
  
    @Get("/anyone")
    async publicInformation(){
        return  "this can be seen by anyone";
    }

    @Post('register')
    async register(@Body() registerDTO: RegisterDTO) {
        const user = await this.userService.create(registerDTO);
        const payload = {
            email: user.email,
        };

        const token = await this.authService.signPayload(payload);
        return { user, token };
    }

    
    @Post('login')
    async login(@Body() loginDTO: LoginDTO) {
        const user = await this.userService.findByLogin(loginDTO);
        const payload = {
            email: user.email,
        };
        const token = await this.authService.signPayload(payload);
        return { user, token};
    }
    
}