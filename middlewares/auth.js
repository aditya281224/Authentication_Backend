const jwt = require("jsonwebtoken");
require("dotenv").config();

exports.auth = async (req, res, next) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Token missing",
      });
    }

    try {
      const decode = jwt.verify(token, process.env.JWT_SECRET);
      req.existingUser = decode;
      next(); // move next() here
    } catch (error) {
      return res.status(401).json({
        success: false,
        message: "Token is invalid",
      });
    }
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Something went wrong",
    });
  }
};

exports.isStudent = async (req, res, next) => {
  try {
    if (req.existingUser.role !== "student") {
      return res.status(401).json({
        success: false,
        message: "Access denied: not a student",
      });
    }
    next();
  } catch (error) {
    console.log(error);
    return res.status(401).json({
      success: false,
      message: "Role not matching",
    });
  }
};

exports.isAdmin = async (req, res, next) => {
  try {
    if (req.existingUser.role !== "Admin") {
      return res.status(401).json({
        success: false,
        message: "Access denied: not an admin",
      });
    }
    next();
  } catch (error) {
    console.log(error);
    return res.status(401).json({
      success: false,
      message: "Role not matching",
    });
  }
};
 