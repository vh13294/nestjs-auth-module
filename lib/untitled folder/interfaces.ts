import { MailData } from '@sendgrid/helpers/classes/mail';

export type EmailMetaData = Pick<MailData, 'to' | 'from' | 'subject'>;

export type EmailData = Pick<MailData, 'to' | 'from' | 'subject'> &
  ({ text: string } | { html: string });
