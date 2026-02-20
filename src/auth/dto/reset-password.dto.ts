import { ApiProperty } from '@nestjs/swagger';
import { IsString, MinLength, Matches } from 'class-validator';

const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

export class ResetPasswordDto {
  @ApiProperty({ description: 'Token from forgot-password email/link' })
  @IsString()
  token: string;

  @ApiProperty({ example: 'NewSecureP@ss1', minLength: 8 })
  @IsString()
  @MinLength(8, { message: 'Password must be at least 8 characters' })
  @Matches(PASSWORD_REGEX, {
    message:
      'Password must contain at least one uppercase, one lowercase, one number and one special character (@$!%*?&)',
  })
  newPassword: string;
}
