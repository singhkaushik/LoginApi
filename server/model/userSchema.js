const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const JWT = require("jsonwebtoken");
const { Schema } = mongoose;
const userSchema = new Schema(
  {
    name: {
      type: String,
      required: [true, "Name is required!"],
      trim: true,
    },

    email: {
      type: String,
      lowercase: true,
      unique: [true, "already registered"],
    },
    phone: {
      type: Number,
    },
    password: {
      type: String,
      select: false,
    },

    forgotPasswordToken: {
      token: String,
    },
    forPasswordExpiryDate: {
      type: Date,
    },
  },
  {
    timestamps: true,
  }
);
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }
  this.password = await bcrypt.hash(this.password, 10);
  return next();
});
userSchema.methods = {
  jwtToken() {
    {
      return JWT.sign(
        {
          id: this._id,
          email: this.email,
        },
        process.env.SECRET,
        { expiresIn: "24h" }
      );
    }
  },
};

const userModel = mongoose.model("user", userSchema);
module.exports = userModel;
