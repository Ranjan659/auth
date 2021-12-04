import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from 'src/types/user';
import { RegisterDTO } from './dto/register.dto';
import * as bcrypt from 'bcrypt';
import { LoginDTO } from 'src/auth/dto/login.dto';
import { Payload } from 'src/types/payload';
// import * as sgMail from '@sendgrid/mail'


// sgMail.setApiKey(process.env.API_KEY);

@Injectable()
export class UserService {

    constructor(
        @InjectModel('User') private userModel: Model<User>,
      ) {}

      async create(RegisterDTO: RegisterDTO) {
        const { email, username } = RegisterDTO;
        const user = await this.userModel.findOne({ email  });
        const userN = await this.userModel.findOne({ username })
        if (user) {
          throw new HttpException('Email already exists', HttpStatus.BAD_REQUEST);
        }else if(userN){
          throw new HttpException('Username already exists', HttpStatus.BAD_REQUEST);
        }
    
        const createdUser = new this.userModel(RegisterDTO);
       
        await createdUser.save();
        return this.sanitizeUser(createdUser);
      }
     
      
      async findByLogin(UserDTO: LoginDTO) {
        const { email, password } = UserDTO;
        const user = await this.userModel.findOne({ email });
        if (!user) {
          throw new HttpException('user doesnt exists', HttpStatus.BAD_REQUEST);
        }
        if (await bcrypt.compare(password, user.password)) {
          return this.sanitizeUser(user)
        } else {
          throw new HttpException('invalid credential', HttpStatus.BAD_REQUEST);
        }
      }
      sanitizeUser(user: User) {
        const sanitized = user.toObject();
        delete sanitized['password'];
        delete sanitized['role'];
        return sanitized;
      }


      // the new methods
      async findByPayload(payload: Payload) {
        const { email } = payload;
        return await this.userModel.findOne({ email });
      }
    
}