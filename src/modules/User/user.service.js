import mongoose from "mongoose";
import { User } from "./user.model.js";

const addUser = async (userBody) => {
  const user = new User(userBody);
  const saveUser = await user.save();
  return saveUser;
};

const getAllUsers = async () => {
  const users = await User.find({});
  return users;
};

const getSingleUser = async (userId) => {
  const isValidObjectId = mongoose.Types.ObjectId.isValid(userId);
  if (!isValidObjectId) {
    return null;
  }

  const user = await User.findById(userId);
  return user;
};

const updateUser = async (userId, userBody) => {
  const isValidObjectId = mongoose.Types.ObjectId.isValid(userId);
  if (!isValidObjectId) {
    return null;
  }

  const user = await User.findByIdAndUpdate(userId, userBody, {
    new: true,
  });
  return user;
};

const deleteUser = async (userId) => {
  const isValidObjectId = mongoose.Types.ObjectId.isValid(userId);
  if (!isValidObjectId) {
    return null;
  }

  const user = await User.findByIdAndDelete(userId);
  return user;
};

export const userService = {
  addUser,
  getAllUsers,
  getSingleUser,
  updateUser,
  deleteUser,
};
