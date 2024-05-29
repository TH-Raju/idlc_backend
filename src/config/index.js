import dotenv from "dotenv";
import path from "path";

dotenv.config({ path: path.join(process.cwd(), ".env") });

export default {
  port: process.env.PORT || 8000,
  site_url: process.env.SITE_URL,
  node_env: process.env.NODE_ENV,
  DB_URL: process.env.DB_URL,
  jwt_access_token: process.env.JWT_ACCESS_TOKEN,
  access_secret: process.env.ACCESS_TOKEN_SECRET,
  refresh_secret: process.env.REFRESH_TOKEN_SECRET,
  smtp_username: process.env.SMTP_USERNAME,
  smtp_password: process.env.SMTP_PASSWORD,
  otp_expire_time: process.env.OTP_EXPIRY_TIME,
};
