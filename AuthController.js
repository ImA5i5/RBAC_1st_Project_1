const User = require("../model/AuthModel");
const bcrypt = require("bcrypt");
const sendEmail = require("../helper/sendEmail");
const otpModel = require("../model/otpModel");
const jwt = require("jsonwebtoken");

class AuthController {
  async registerPage(rreq, res) {
    try {
      res.render("register");
    } catch (error) {
      console.log(error);
    }
  }

  async Register(req, res) {
    try {
      const { name, email, password, phone, role } = req.body;

      if (!name || !email || !password || !phone || !role) {
        req.flash("error", "required all fields");
        return res.redirect("/register");
      }

      //validate for name
      const nameRegex = /^[a-zA-Z ]{2,100}$/;
      if (!nameRegex.test(name)) {
        req.flash("error", "Invalid name");
        return res.redirect("/register");
      }

      //validate for email
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        req.flash("error", "Invalid email format");
        return res.redirect("/register");
      }

      //validate for password
      if (password.length < 8) {
        req.flash("error", "Password must be at least 6 characters");
        return res.redirect("/register");
      }

      //validate for phone
      const phoneRegex = /^[0-9]{10}$/;
      if (!phoneRegex.test(phone)) {
        req.flash("error", "Invalid phone number");
        return res.redirect("/register");
      }

      const existingUser = await User.findOne({ email });
      if (existingUser) {
        req.flash("error", "Email already exists");
        return res.redirect("/register");
      }

      const salt = bcrypt.genSaltSync(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const newUser = new User({
        name,
        phone,
        email,
        password: hashedPassword,
        role
      });

      const setUser = await newUser.save();

      //otp save
      sendEmail(req, setUser);

      if (setUser) {
        req.flash("success", "Registration successful! Please log in.");
        return res.redirect("/verify_otp");
      } else {
        req.flash("error", "Registration failed");
        res.redirect("/register");
      }
    } catch (error) {
      console.error("Register Error:", error);
      req.flash("error", "Something went wrong");
      res.redirect("/register");
    }
  }

  async verify_otpPage(req, res) {
    try {
      return res.render("verify_otp");
    } catch (error) {
      console.log(error.message);
    }
  }

  async Verify_otp(req, res) {
    try {
      const { email, otp } = req.body;

      if (!email || !otp) {
        req.flash("error", "all field are required");
        return res.redirect("/verify_otp");
      }

      const existingUser = await User.findOne({ email });
      if (!existingUser) {
        req.flash("error", "Email doesn't exists");
        return res.redirect("/register");
      }

      // Check if email is already verified
      if (existingUser.is_verify) {
        req.flash("error", "Email is already verified");
        return res.redirect("/verify_otp");
      }

      // Check if there is a matching email verification OTP
      const emailVerification = await otpModel.findOne({
        userId: existingUser._id,
        otp,
      });

      //   if(emailVerification){
      //      if (!existingUser.is_verify) {
      //       // console.log(existingUser);
      //       await sendEmail(req, existingUser);
      //       req.flash("error", "Invalid OTP, new OTP sent to your email");
      //      return res.redirect("/verify_otp");
      //     }
      //     req.flash("error", "Invalid OTP");
      //       return res.redirect("/verify_otp");
      //   }

      if (!emailVerification) {
        // No matching OTP
        await sendEmail(req, existingUser);
        req.flash(
          "error",
          "Invalid OTP. A new OTP has been sent to your email."
        );
        return res.redirect("/verify_otp");
      }

      // Check if OTP is expired
      const currentTime = new Date();
      // 10 * 60 * 1000 calculates the expiration period in milliseconds(10 minutes).
      const expirationTime = new Date(
        emailVerification.createdAt.getTime() + 10 * 60 * 1000
      );

      if (currentTime > expirationTime) {
        // OTP expired, send new OTP
        await sendEmail(req, existingUser);
        req.flash("error", "OTP expired, new OTP sent to your email");
        return res.redirect("/verify_otp");
      }

      // OTP is valid and not expired, mark email as verified
      existingUser.is_verify = true;
      await existingUser.save();

      // Delete email verification document
      await otpModel.deleteMany({ userId: existingUser._id });
      req.flash("success", "Email verified successfully");
      return res.redirect("/login");
    } catch (error) {
      console.log(error.message);
      req.flash("error", "Unable to verify email, please try again later");
      return res.redirect("/register");
    }
  }

  async loginPage(req, res) {
    try {
      res.render("login");
    } catch (error) {
      console.log(error);
    }
  }

  async Login(req, res) {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        res.flash("error", "all fields are required");
        return res.redirect("/login");
      }

      const user = await User.findOne({ email });
      if (!user) {
        req.flash("error", "Invalid email");
        return res.redirect("/login");
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        req.flash("error", "invalid password");
        return res.redirect("/login");
      }

      const accessToken = jwt.sign(
        { id: user._id, name: user.name, email: user.email, phone: user.phone,role: user.role},
        process.env.JWT_SECRET_ACCESS,
        { expiresIn: process.env.JWT_ACCESS_EXP }
      );

      const refreshToken = jwt.sign(
        { id: user._id, name: user.name, email: user.email, phone: user.phone,role: user.role },
        process.env.JWT_SECRET_REFRESH,
        { expiresIn: process.env.JWT_REFRESH_EXP }
      );

      if (!accessToken || !refreshToken) {
        req.flash("error", "Cannot generate token. Please try again.");
        return res.redirect("/login");
      }

      // Store accessToken in cookie or send in header
      res.cookie("accessToken", accessToken, {
        httpOnly: true,
        secure: false,
        sameSite: "strict",
        maxAge: 10 * 60 * 1000,
      });

      // Store refreshToken in HTTP-only cookie
      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: false,
        sameSite: "strict",
        maxAge: 1 * 24 * 60 * 60 * 1000,
      });
      return res.redirect("/dashboard");
    } catch (error) {
      console.log(error.message);

      req.flash("error", "Failed to log in. Try again later.");
      return res.redirect("/login");
    }
  }

  async refreshToken(req, res) {
    try {
      const token = req.cookies.refreshToken;
      if (!token) {
        req.flash("error", "Refresh token not found");
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET_REFRESH);

      const newAccessToken = jwt.sign(
        {
          id: decoded.id,
          name: decoded.name,
          email: decoded.email,
          phone: decoded.phone,
          role: decoded.role,
        },
        process.env.JWT_SECRET_ACCESS,
        { expiresIn: process.env.JWT_ACCESS_EXP }
      );

      res.cookie("accessToken", newAccessToken, {
        httpOnly: true,
        secure: false,
        sameSite: "strict",
        maxAge: 10 * 60 * 1000,
      });

      res.redirect("/dashboard");
    } catch (error) {
      console.error("Invalid Refresh Token");
      res.redirect("/login");
    }
  }

  async Auth(req, res, next) {
    try {
      if (req.user) {
        next();
      } else {
        req.flash("error", "can not auth check");
        return res.redirect("/login");
      }
    } catch (error) {
      console.log(error.message);
    }
  }

  async dashboard(req, res) {
    try {
      res.render("dashboard", { data: req.user });
    } catch (error) {
      console.log(error.message);
    }
  }

  async logout(req, res) {
    try {
      res.clearCookie("accessToken");
      res.clearCookie("refreshToken");
      res.redirect("/login");
    } catch (error) {
      console.log(error.message);
    }
  }

  async updatePassword(req, res) {
    try {
      res.render("updatepassword");
    } catch (error) {
      console.log(error.message);
    }
  }

  async updatePasswordPage(req, res) {
    try {
      const userId = req.user.id;
      const { currentPassword, newPassword } = req.body;
      if (!currentPassword || !newPassword) {
        req.flash("error", "all field are required");
        return res.redirect("/update_password");
      }

      const user = await User.findById(userId);
      const isMatch = await bcrypt.compare(currentPassword, user.password);

      if (!isMatch) {
        req.flash("error", "Current password is incorrect");
        return res.redirect("/update_password");
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      user.password = hashedPassword;
      await user.save();

      // Clear auth cookies and force re-login
      res.clearCookie("accessToken");
      res.clearCookie("refreshToken");

      req.flash("success", "Password updated. Please log in again.");
      res.redirect("/login");
    } catch (error) {
      console.log(error.message);
      req.flash("error", "Something went wrong");
      res.redirect("/update-password");
    }
  }
}
module.exports = new AuthController();
