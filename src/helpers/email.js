import { createTransport } from "nodemailer";
import config from "../config/index.js";

const transporter = createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: config.smtp_username,
    pass: config.smtp_password,
  },
  tls: {
    rejectUnauthorized: false,
  },
});

const emailWithNodemailer = async (emailData) => {
  try {
    const mailOptions = {
      from: config.smtp_username, // sender address
      to: emailData.email, // list of receivers
      subject: emailData.subject, // Subject line
      html: emailData.html, // html body
    };

    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent %s", info.response);
  } catch (error) {
    console.error("Error sending mail", error);
    throw error;
  }
};

export default emailWithNodemailer;
