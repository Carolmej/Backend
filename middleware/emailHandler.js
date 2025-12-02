import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: Number(process.env.MAIL_PORT),
  secure: process.env.MAIL_PORT === '465',
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
  tls: {
    rejectUnauthorized: true
  },
  pool: process.env.MAIL_POOL === 'true' || false,
  maxConnections: Number(process.env.MAIL_MAX_CONN),
  maxMessages: Number(process.env.MAIL_MAX_MSG)
});

const verifyTransport = async () => {
  try {
    await transporter.verify();
    console.log('SMTP verified');
  } catch (err) {
    console.error('SMTP verification failed:', err);
    throw err;
  }
};

const sendMail = async (to, subject, html) => {
  const info = await transporter.sendMail({ from: process.env.MAIL_FROM, to, subject, html });
  return info;
};

export { verifyTransport, sendMail };