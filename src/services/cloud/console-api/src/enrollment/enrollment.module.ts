import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from '../auth/auth.module';
import { EnrollmentToken, EnrollmentTokenSchema } from '../schemas/enrollment-token.schema';
import { EnrollmentController } from './enrollment.controller';
import { EnrollmentService } from './enrollment.service';

@Module({
  imports: [
    AuthModule,
    MongooseModule.forFeature([{ name: EnrollmentToken.name, schema: EnrollmentTokenSchema }]),
  ],
  controllers: [EnrollmentController],
  providers: [EnrollmentService],
  exports: [EnrollmentService],
})
export class EnrollmentModule {}
