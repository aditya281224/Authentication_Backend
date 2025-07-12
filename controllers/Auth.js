const bcrypt = require("bcrypt");
const User = require("../model/User");
const jwt=require("jsonwebtoken");
require("dotenv").config();

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


exports.login=async (req,res)=>{
  try{

    //  data fetch
    const {email,password}=req.body;

    // validation on email and password

    // 1st no email and password in request

    if(!email || !password){
      return res.status(400).json({
        success:false,
        message:"Enter email and password"
      })
    }

    // 2nd if user exists with the email

    let existingUser=await User.findOne({email});

    if(!existingUser){
      return res.status(401).json({
        succss:false,
        message:"No such user exists"
      })
    }

    // verify password and generate a token
    const payload={
      email:existingUser.email,
      id:existingUser._id,
      role:existingUser.role


    }
    if(await bcrypt.compare(password,existingUser.password)){

      // password is matched

      let token =jwt.sign(payload,process.env.JWT_SECRET,{
        expiresIn:"2h"
      })
      existingUser=existingUser.toObject();
      existingUser.token=token;
      existingUser.password=undefined;
      const options={
        expires:new Date(Date.now()+3*24*60*60*1000),
        httpOnly:true

      }
      res.cookie("token",token,options).status(200).json({
        success:true,
        token,
        existingUser,
        message:"User Logged in successfully"
      })

    }
    else
    {
      return res.status(403).json({
        success:false,
        message:"Password incorrect"
      })
    }


    

  }
  catch(error){
    console.log(error)
    return res.status(500).json({
      success:false,
      message:"Login failed"
    })
  }
}