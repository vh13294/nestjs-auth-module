import { BadRequestException, Controller, Get, Param } from '@nestjs/common';

import { EmailService } from 'nestjs-email-service';

@Controller()
export class RegisterController {
  constructor(private readonly emailService: EmailService) {}

  @Get('sendEmail')
  async sendEmail(): Promise<void> {
    const emailMetaData = {
      to: 'jam.com',
      from: 'vh.uk',
      subject: 'hi',
    };
    const templatePath = 'test.mjml';

    try {
      await this.emailService.sendMjml(emailMetaData, templatePath, {
        name: 'Bro',
      });
    } catch (error) {
      throw new BadRequestException(error.response.body.errors[0]);
    }
  }

  @Get('viewEmail/:id')
  async viewEmail(@Param('id') id: string): Promise<string> {
    // 1 to 7 tests
    const templatePath = `${id}.mjml`;

    try {
      return await this.emailService.getRenderedMjml(templatePath, {
        name: 'Bro',
      });
    } catch (error) {
      throw new BadRequestException(error);
    }
  }
}
