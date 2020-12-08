import { Inject, Injectable } from '@nestjs/common';

import { EmailModuleOptions } from './email-options.interface';
import { EMAIL_MODULE_OPTIONS } from './email.constants';

import { compileTemplate, registerPartials } from './helpers';
import { EmailData, EmailMetaData } from './interfaces';

import { ClientResponse } from '@sendgrid/client/src/response';
import { send, setApiKey } from '@sendgrid/mail';
import { join } from 'path';
import { promises as fs } from 'fs';

@Injectable()
export class EmailService {
  constructor(
    @Inject(EMAIL_MODULE_OPTIONS)
    private readonly emailModuleOptions: EmailModuleOptions,
  ) {
    if (!this.emailModuleOptions.apiKey) {
      throw new Error('The app key must not be empty');
    } else {
      setApiKey(emailModuleOptions.apiKey);
    }

    if (!this.emailModuleOptions.templateDir) {
      throw new Error('The template directory location must not be empty');
    }

    if (this.emailModuleOptions.partialsDir) {
      registerPartials(this.emailModuleOptions.partialsDir);
    }
  }

  private async getFile(relativePath: string): Promise<string> {
    const path = join(this.emailModuleOptions.templateDir, relativePath);
    return fs.readFile(path, 'utf-8');
  }

  // for testing
  public async getRenderedMjml(
    mjmlPath: string,
    templateData: unknown,
  ): Promise<string> {
    const mjml = await this.getFile(mjmlPath);
    const compiledHtml = compileTemplate(mjml, templateData);
    return compiledHtml;
  }

  public async send(emailData: EmailData): Promise<[ClientResponse, {}]> {
    return send(emailData);
  }

  public async sendMjml(
    metaData: EmailMetaData,
    mjmlPath: string,
    templateData: unknown,
  ): Promise<[ClientResponse, {}]> {
    const mjml = await this.getFile(mjmlPath);
    const compiledHtml = compileTemplate(mjml, templateData);
    const emailData = {
      ...metaData,
      html: compiledHtml,
    };
    return send(emailData);
  }

  // todo add another method
  // [{to: a.com, html: directory, dataToRender: {}}, {to: b.com, html: directory, dataToRender: {}}]

  // [{to: a.com, html | text: 1}, {to: b.com, html | text: 2}]
  public async sendMultiple(
    emailData: EmailData[],
  ): Promise<[ClientResponse, {}]> {
    return send(emailData);
  }
}
