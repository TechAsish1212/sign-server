import userModel from "../models/userModel.js";

export const getUserData =async (req,res)=>{

    try {

        const userId =req.user?.id;
        const user =await userModel.findById(userId);
        if(!user)
        {
            return res.status(400).json({success:false,message:"User not found."});
        }

        res.status(200).json({
            success:true,
            userData: {
                name:user.name,
                isAccountVerified:user.isAccountVerified,

            }
        })
        
    } catch (error) {
        
        return res.status(500).json({success:false,message:error.message});
    }
}