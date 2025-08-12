const jwt=require("jsonwebtoken");

const AuthCheck=(req,res,next)=>{
    const token = req.cookies.accessToken;
    
    if(!token){
        req.flash("error","access token not found")
        return res.redirect("/login")
    }

    jwt.verify(token, process.env.JWT_SECRET_ACCESS, (err, data) => {
    if (err) {
      // Token expired, try refreshing
      return res.redirect("/refresh-token");
    }
    req.user = data;
    next();
  });
}

module.exports=AuthCheck