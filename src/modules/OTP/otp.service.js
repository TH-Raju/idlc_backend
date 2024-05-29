import config from "../../config/index.js";
import emailWithNodemailer from "../../helpers/email.js";
import OTP from "./otp.model.js";

const sendOTP = async (name, sentTo, receiverType, purpose) => {
  const otp = Math.floor(100000 + Math.random() * 900000);
  const subject =
    purpose === "email-verification"
      ? "Email verification code"
      : "Forgot password code";
  //sending email if receiverType is email
  if (receiverType === "email") {
    const emailData = {
      email: sentTo,
      subject: subject,
      html: `
        <h1>Hello, ${name}</h1>
        <p>Your One Time Code is <h3>${otp}</h3> to verify your account</p>
        <small>This Code is valid for ${config.otp_expire_time} minutes</small>
      `,
    };
    await emailWithNodemailer(emailData);
  }

  const otpExpiryTime = parseInt(process.env.OTP_EXPIRY_TIME) || 3;
  const expiredAt = new Date();
  expiredAt.setMinutes(expiredAt.getMinutes() + otpExpiryTime);

  const newOTP = new OTP({
    sentTo,
    receiverType,
    purpose,
    otp,
    expiredAt,
  });
  const savedOtp = await newOTP.save();

  // Schedule deletion of OTP after 3 minutes
  setTimeout(async () => {
    try {
      await OTP.findByIdAndDelete(savedOtp._id);
      console.log("OTP deleted successfully after expiry.");
    } catch (error) {
      console.error("Error deleting OTP after expiry:", error);
    }
  }, 180000);

  return true;
};

const checkOTPByEmail = async (sentTo) => {
  return await OTP.findOne({
    sentTo: sentTo,
    status: "pending",
    expiredAt: { $gt: new Date() },
  });
};

const verifyOTP = async (sentTo, receiverType, purpose, otp) => {
  const otpData = await OTP.findOne({
    sentTo,
    receiverType,
    purpose,
    otp,
    expiredAt: { $gt: new Date() },
    status: { $eq: "pending" },
  });
  if (!otpData) {
    return null;
  }
  otpData.status = "expired";
  otpData.verifiedAt = new Date();
  await otpData.save();
  return otpData;
};

const checkOTPValidity = (sentTo) => {
  return OTP.findOne({
    sentTo: sentTo,
    expiredAt: { $gt: new Date() },
    status: "verified",
  });
};

const updateOTP = async (otpId, otpBody) => {
  const otpData = await OTP.findById(otpId);
  if (!otpData) {
    return false;
  }
  Object.assign(otpData, otpBody);
  await otpData.save();
  return true;
};

const deleteOTP = async (otpId) => {
  return await OTP.findByIdAndDelete(otpId);
};

const verifiedUser = async (otp) => {
  const otpData = await OTP.find({ otp: otp });
  return otpData;
};

export const otp = {
  sendOTP,
  checkOTPByEmail,
  verifyOTP,
  checkOTPValidity,
  updateOTP,
  deleteOTP,
  verifiedUser,
};
