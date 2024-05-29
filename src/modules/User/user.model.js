import mongoose, { model } from "mongoose";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
dotenv.config();

const userSchema = new mongoose.Schema(
  {
    fullName: {
      type: String,
    },
    phone: {
      type: String,
      required: [true, "Phone Number is required"],
      lowercase: true,
    },
    email: {
      type: String,
      required: [true, "Email is required"],
    },
    address: {
      type: String,
    },
    password: {
      type: String,
      required: [true, "password is required"],
      minlength: [6, "Minimum password length is 6 characters"],
    },
    photo: {
      type: String,
      default: "/uploads/profile/default-user.jpg",
    },
    role: {
      type: String,
      enum: ["customer", "vendor", "admin", "super_admin"],
      default: "customer",
    },
  },
  { timestamps: true }
);

userSchema.pre("save", async function (next) {
  const salt = await bcrypt.genSalt();
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

export const User = model("User", userSchema);

export default model("User", userSchema);
