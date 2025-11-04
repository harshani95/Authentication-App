import { IsEmail, IsString } from 'class-validator';

export class LoginUserDto {
  @IsString()
  @IsEmail()
  username: string;

  @IsString()
  password: string;
}
