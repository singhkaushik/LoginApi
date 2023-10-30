const userModel = require("../model/userSchema.js");
const emailValidator = require("email-validator");
const bcrypt = require("bcrypt");

const signup = async (req, res, next) => {
  const { name, phone, email, password, confirmPassword } = req.body;

  if (!name || !email || !phone || !password || !confirmPassword) {
    return res.status(400).json({
      success: false,
      message: "All fields are required",
    });
  }

  const validEmail = emailValidator.validate(email);

  if (!validEmail) {
    return res.status(400).json({
      success: false,
      message: "Please provide a valid email address",
    });
  }
  const existingUser = await userModel.findOne({ email });
  if (existingUser) {
    return res.status(400).json({
      success: false,
      message: "An account already exists with the provided email address",
    });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({
      success: false,
      message: "Password and Confirm Password don't match",
    });
  }

  try {
    const userInfo = new userModel(req.body);
    const result = await userInfo.save();
    if (result) {
      return res.status(200).json({
        success: true,
        data: result,
      });
    }
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({
        success: false,
        message: "An account already exists with the provided email address",
      });
    }

    return res.status(400).json({
      success: false,
      message: err.message,
    });
  }
};

const signin = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: "All fields are required",
    });
  }

  try {
    const user = await userModel
      .findOne({
        email,
      })
      .select("+password");

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    const token = user.jwtToken();
    user.password = undefined;

    const cookieOption = {
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true,
    };

    res.cookie("token", token, cookieOption);
    res.status(200).json({
      success: true,
      data: user,
    });
  } catch (e) {
    res.status(400).json({
      success: false,
      message: e.message,
    });
  }
};

const getUser = async (req, res, next) => {
  const userId = req.user.id;

  try {
    const user = await userModel.findById(userId);
    return res.status(200).json({
      success: true,
      data: user,
    });
  } catch (e) {
    return res.status(400).json({
      success: false,
      message: e.message,
    });
  }
};

const logout = (req, res, next) => {
  try {
    const cookieOption = {
      expires: new Date(),
      httpOnly: true,
    };
    res.cookie("token", null, cookieOption);
    res.status(200).json({
      success: true,
      message: "Logged Out",
    });
  } catch (e) {
    return res.status(400).json({
      success: false,
      message: e.message,
    });
  }
};

module.exports = {
  signup,
  signin,
  getUser,
  logout,
};
