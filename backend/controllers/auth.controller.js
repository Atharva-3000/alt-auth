import bcryptjs from "bcryptjs";
import { User } from "../models/user.model.js";
import { generateTokenAndSetCookie } from "../utils/generateTokenAndSetCookie.js";
import {
  sendPasswordResetEmail,
  sendVerificationEmail,
  sendWelcomeEmail,
  sendResetSuccessEmail
} from "../mailtrap/emails.js";
import crypto from "crypto";
import dotenv from "dotenv";
dotenv.config();

// signup endpoint

export const signup = async (req, res) => {
  const { name, email, password } = req.body;

  try {
    if (!email || !password || !name) {
      throw new error("All fields are required");
    }
    const alreadyExists = await User.findOne({ email });
    if (alreadyExists) {
      return res
        .status(400)
        .json({ success: false, message: "User already exists" });
    }

    const hashedPassword = await bcryptjs.hash(password, 12);
    const verificationToken = Math.floor(
      100000 + Math.random() * 900000
    ).toString();

    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      verificationToken,
      verificationTokenExpires: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
    });
    await user.save();
    generateTokenAndSetCookie(res, user._id);
    sendVerificationEmail(user.email, verificationToken);
    res.status(201).json({
      success: true,
      message: "User created successfully",
      user: {
        ...user._doc,
        password: undefined,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(400).json({ success: false, message: error.message });
  }
};

// verify email endpoint

export const verifyEmail = async (req, res) => {
  const { code } = req.body;
  try {
    const user = await User.findOne({
      verificationToken: code,
      verificationTokenExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired verification code",
      });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;
    await user.save();

    await sendWelcomeEmail(user.email, user.name);

    res.status(200).json({
      success: true,
      message: "Email verified successfully",
      user: {
        ...user._doc,
        password: undefined,
      },
    });
  } catch (error) {
    console.log({ success: false, message: "error in verifyEmail ", error });
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// login endpoint

export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!email || !password) {
      throw new Error("All fields are required");
    }
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "Invalid credentials" });
    }
    const isPasswordCorrect = await bcryptjs.compare(password, user.password);
    if (!isPasswordCorrect) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid credentials" });
    }
    const resetToken = Math.floor(100000 + Math.random() * 900000).toString();
    generateTokenAndSetCookie(res, user._id);
    user.lastLogin = new Date();
    await user.save();

    res.status(200).json({
      success: true,
      message: "Logged in successfully",
      user: {
        ...user._doc,
        password: undefined,
      },
    });
  } catch (error) {
    console.log({ success: false, message: "error in login ", error });
    console.error(error);
    res.status(400).json({ success: false, message: error.message });
  }
};
export const logout = async (req, res) => {
  res.clearCookie("token").json({ message: "Logged out successfully" });
  res.status(200).send({ success: true, message: "Logged out successfully" });
};

// forgot password endpoint
export const forgotPassword = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    // getting a new token
    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpiresAt = Date.now() + 60 * 60 * 1000; // 1 hours
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = resetTokenExpiresAt;

    await user.save();
    // send reset mail otp
    await sendPasswordResetEmail(
      user.email,
      `${process.env.CLIENT_URL}/reset-password/${resetToken}`
    );
    res.status(200).json({
      success: true,
      message: "Instructions to reset password has been sent to your email !",
    });
  } catch (error) {
    console.error(error);
    res.status(400).json({ success: false, message: error.message });
  }
};

// reset password endpoint
export const resetPassword = async (req, res) => {
  try {
    const token = req.params.token;
    const { password } = req.body;

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid or expired token" });
    }
    // update password
    const hashedPassword = await bcryptjs.hash(password, 12);
    user.password = hashedPassword;

    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    sendResetSuccessEmail(user.email);
  } catch (error) {
    console.error(error);
    res.status(400).json({ success: false, message: error.message });
  }
};
