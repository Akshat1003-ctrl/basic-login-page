const nodemailer = require('nodemailer');

const sendEmail = async (options) => {
    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        auth: {
            user: process.env.EMAIL_USERNAME,
            pass: process.env.EMAIL_PASSWORD,
        },
    });

    const mailOptions = {
        from: 'Your Company <noreply@yourcompany.com>',
        to: options.to,
        subject: options.subject,
        html: options.text,
    };

    await transporter.sendMail(mailOptions);
};

module.exports = sendEmail;