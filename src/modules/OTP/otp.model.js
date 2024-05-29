import { Schema, model } from "mongoose";

const otpSchema = new Schema(
  {
    sentTo: {
      type: String,
      required: [true, "Receiver source is required"],
    },
    receiverType: { type: String, enum: ["email", "phone"], default: "email" },
    purpose: {
      type: String,
      enum: ["email-verification", "forget-password"],
      default: "email-verification",
    },
    otp: { type: String, required: [true, "OTP is must be given"], trim: true },
    expiredAt: {
      type: Date,
      required: [true, "ExpiredAt is must be given"],
      trim: true,
    },
    verifiedAt: { type: Date, required: false, trim: true },
    status: {
      type: String,
      enum: ["verified", "pending", "expired"],
      default: "pending",
    },
  },
  {
    timestamps: true,
  }
);

const OTP = model("OTP", otpSchema);
export default OTP;
