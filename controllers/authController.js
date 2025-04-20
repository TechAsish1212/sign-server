import bcrypt from "bcryptjs";
import jwt  from "jsonwebtoken";
import userModel from "../models/userModel.js";
import transporter from "../config/nodemailer.js";
import { text } from "express";
import { EMAIL_VERIFY_TEMPLATE,PASSWORD_RESET_TEMPLATE } from "../config/emailTemplates.js";

// user register

export const register =async (req,res)=>{

    const { name, email, password } =req.body;

    if(!name || !email || !password)
    {
        return res.status(400).json({success:false,message:"All fields are required."});
    }
    try {

        const existinigUser =await userModel.findOne({email});

        if(existinigUser)
        {
            return res.status(409).json({success: false,message: 'User already exists.'})
        }
        const hashedPassword =await bcrypt.hash(password,10);

        const user =new userModel({name,email,password:hashedPassword});
        await user.save();

        const token =jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});

        res.cookie('token',token,{
            httpOnly:true,
            secure: process.env.NODE_ENV ==='production',
            sameSite:process.env.NODE_ENV ==='production'? 'none':'strict',
            maxAge:7*24*60*60*1000,
        });

        // sending welcome message

        const mailOptions ={
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to Tech Asish LTD.',
            html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px; background-color: #f9f9f9;">
            <h2 style="color: #2d3748;">👋 Welcome, ${name}!</h2>
            <p style="font-size: 16px; color: #4a5568;">
                We're thrilled to have you join <strong>Tech Asish LTD</strong>. Your account has been successfully created with the email:
            </p>
            <p style="font-size: 18px; font-weight: bold; color: #1a202c;">${email}</p>
            <div style="margin: 20px 0; padding: 15px; background-color: #edf2f7; border-left: 4px solid #3182ce; border-radius: 5px;">
                <p style="margin: 0; color: #2c5282;">Start exploring our services and make the most out of your journey with us.</p>
            </div>
            <p style="font-size: 14px; color: #718096;">If you have any questions or need help, feel free to contact us anytime.</p>
            <p style="color: #4a5568;">Cheers,<br/><strong>Tech Asish Team</strong></p>
        </div>
    `
        }

        await transporter.sendMail(mailOptions);

        res.status(200).json({success:true})
        
    } catch (error) {
        res.status(500).json({success: false, message: error.message});
    }
}

// user login

export const login =async(req,res)=>{
    const {email,password} =req.body;

    if(!email || !password)
    {
        return res.status(400).json({success:false,message:"Email or Password are required."});
    }
    try {
        
        // to check email exist or not 

        const user=await userModel.findOne({email});
        if(!email)
        {
            return res.status(400).json({success:false,message:"Email Invalid"});
        }

        //to check password is valid or not

        const isPassMatch=await bcrypt.compare(password,user.password);
        if(!isPassMatch)
        {
            return res.status(400).json({success:false,message:"Password Invalid."});
        }

        const token =jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});
        res.cookie('token',token,{
            httpOnly:true,
            secure: process.env.NODE_ENV ==='production',
            sameSite:process.env.NODE_ENV ==='production'? 'none':'strict',
            maxAge:7*24*60*60*1000,
        });
        res.status(200).json({success:true})

    } catch (error) {
        return res.json({success:false,message:error.message})
    }
}

// user logout

export const logout=async(req,res)=>{

    try {
        res.clearCookie('token',{
            httpOnly:true,
            secure: process.env.NODE_ENV ==='production',
            sameSite:process.env.NODE_ENV ==='production'? 'none':'strict',
        })
        return res.status(200).json({success:true,message:"Logged Out"});

    } catch (error) {
        return res.status(500).json({success:false,message:error.message});
    }
}


// otp verify sending message

export const sendVerifyOtp = async (req, res) => {
    try {
        const userId = req.user?.id;

        if (!userId) {
            return res.status(400).json({ success: false, message: "User ID not found in request." });
        }

        const user = await userModel.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        if (user.isAccountVerified) {
            return res.json({ success: false, message: "Account is already verified." });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 10 * 60 * 1000;

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            html:EMAIL_VERIFY_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email),
        };

        await transporter.sendMail(mailOptions);

        return res.json({ success: true, message: 'Verification OTP sent to email.' });

    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};


// verify Email

export const verifyEmail= async(req,res)=>{
    const {otp} =req.body;
    const userId =req.user?.id;

    if(!otp)
    {
        return res.status(400).json({success:false,message:"OTP required."});
    }
    
    if (!userId) {
        return res.status(401).json({ success: false, message: "Unauthorized request." });
    }

    try {
        const user =await userModel.findById(userId);
        if(!user)
        {
            return res.status(400).json({success:false,message:"User not found"});
        }

        if(user.verifyOtp === "" || user.verifyOtp !==otp)
        {
            return res.status(400).json({success:false,message:"Invalid OTP."});
        }
        if(user.verifyOtpExpireAt < Date.now())
        {
            return res.status(401).json({success:false,message:"Expire OTP."}); 
        }

        user.isAccountVerified=true;
        user.verifyOtp='';
        user.verifyOtpExpireAt=0;

        await user.save();

        return res.status(200).json({success:true,message:"Email Verified Successfully."});

    } catch (error) {
        return res.status(500).json({success:false,message:error.message});
    }
}


// To check user is already logged in or not

export const isAuthenticated =async(req,res)=>{
    try {
        return res.status(200).json({success:true});
    } catch (error) {
        return res.status(500).json({success:false,message:error.message})
    }
}

// send OTP for reset password

export const sendResetOtp =async(req,res)=>{
    const {email} =req.body;

    if(!email)
    {
        res.status(400).json({success:false,message:"Email is required."});
    }
    try {
        
        const user =await userModel.findOne({email});
        if(!user)
        {
            return res.status(400).json({success:false,message:"User not found"});
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user. resetOtp = otp;
        user. resetOtpExpireAt = Date.now() + 15 * 60 * 1000;

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP.',
            html:PASSWORD_RESET_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email),
        };

        await transporter.sendMail(mailOptions);

        return res.status(200).json({success:true,message:"OTP sent to your email."})

    } catch (error) {
        return res.status(500).json({success:false,message:error.message});
    }
}

// Reset user password

export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.status(400).json({ success: false, message: "All fields are required." });
    }

    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(400).json({ success: false, message: "User not found" });
        }

        if (user.resetOtp === '' || user.resetOtp !== otp) {
            return res.status(400).json({ success: false, message: "Invalid OTP." });
        }

        if (user.resetOtpExpireAt < Date.now()) {
            return res.status(400).json({ success: false, message: "OTP Expired." });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;

        await user.save();

        // Send confirmation email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset Successful',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px;">
                    <h2 style="color: #2c3e50;">Your Password Has Been Reset</h2>
                    <p>Hello <strong>${user.name}</strong>,</p>
                    <p>This is to confirm that your password has been successfully changed.</p>
                    <p>If you did not perform this action, please contact our support team immediately.</p>
                    <br/>
                    <p style="color: #888;">Thanks,<br/>Tech Asish Team</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);

        return res.status(200).json({ success: true, message: "Password has been reset successfully." });

    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};
