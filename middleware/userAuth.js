// import jwt from 'jsonwebtoken';

// const userAuth =async(req,res,next)=>{
//     const {token} =req.cookies;

//     if(!token)
//     {
//         return res.status(400).json({success:false,message:"User not Authorizied.Login Again."});
//     }


//     try {

//         const tokenDecode = jwt.verify(token,process.env.JWT_SECRET);

//          if(tokenDecode.id)
//          {
//             req.body.userId =tokenDecode.id;
//          }
//          else
//          {
//             return res.status(400).json({success:false,message:"User not Authorizied.Login Again."});
//          }
//          next();
        
//     } catch (error) {
//         return res.status(500).json({success:false,message:error.message});
//     }
// }

// export default userAuth;

import jwt from 'jsonwebtoken';

const userAuth = async (req, res, next) => {
    const { token } = req.cookies;

    if (!token) {
        return res.status(401).json({ success: false, message: "Unauthorized. Please log in again." });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (decoded?.id) {
            req.user = { id: decoded.id };
            next();
        } else {
            return res.status(401).json({ success: false, message: "Unauthorized. Invalid token." });
        }

    } catch (error) {
        return res.status(401).json({ success: false, message: "Unauthorized. Invalid or expired token." });
    }
};

export default userAuth;
