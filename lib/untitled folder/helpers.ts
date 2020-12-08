import { compile, registerPartial } from 'handlebars';
import { promises as fs } from 'fs';
import mjml2html from 'mjml';
import { join } from 'path';

// compile handlebars {{}} template (in mjml)
export function compileTemplate(rawHtml: string, data: unknown): string {
  const template = compile(rawHtml);
  const templateWithInjectedData = template(data);

  const mjml = mjml2html(templateWithInjectedData, {
    validationLevel: 'strict',
  });
  return mjml.html;
}

// to use partial {{> /layout/header }} // from templateDir
export async function registerPartials(templateDir: string): Promise<void> {
  const files = await fs.readdir(templateDir);

  files.forEach(async (filename) => {
    const matches = /^([^.]+).mjml$/.exec(filename);
    if (!matches) {
      return;
    }
    const name = matches[1];
    const filePath = join(templateDir, `${name}.mjml`);
    const template = await fs.readFile(filePath, 'utf8');
    registerPartial(filePath, template);
  });
}
