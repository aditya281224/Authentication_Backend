const bcrypt = require("bcrypt");
const User = require("../model/User");

exports.signup = async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists",
      });
    }

    //secure password
    let hashedPassword;
    try{
      hashedPassword=await bcrypt.hash(password,10);
    }
    catch(error){
      return res.status(500).json({
        success:false,
        message:"Error in hashing"
      })
    }

    // create entry

    const user = await User.create({
      name,email,password:hashedPassword,role
    })

    return res.status(200).json({
      success:true,
      message:'User created successfully'
    })

  } catch (error) {
    console.error(error)({
      success:false,
      message:'User cannot be registered'
    })
  }
};
