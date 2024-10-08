import mongoose from "mongoose";
import dotnev from "dotenv";
dotnev.config();
export const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("MongoDB connected");
  } catch (error) {
    console.log("MongoDB connection failed" + error);
    process.exit(1); //failure code
  }
};
