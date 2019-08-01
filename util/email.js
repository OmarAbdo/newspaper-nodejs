import nodemailer from 'nodemailer';
import config from './config';

const email = config.MAILER_EMAIL_ID ;
const pass  = config.MAILER_PASSWORD ;

export const smtpTransport = nodemailer.createTransport({
    service: config.MAILER_SERVICE_PROVIDER,
    host: config.MAILER_HOST, //since we're using google SMTP we should allow less secure apps https://myaccount.google.com/lesssecureapps?pli=1
    port: 465,
    secure: true,
    auth: {      
        user: email,
        pass: pass
    },
    tls:{
        rejectUnauthorized: false,
    }
});


export const handlebarsOptions = {
    viewEngine: {
        extname: '.hbs',
        layoutsDir: 'emails/',
        defaultLayout: 'forgot-password-email',
        partialsDir: 'emails/partials'
    },
    viewPath: 'emails/',
    extName: '.hbs'
};