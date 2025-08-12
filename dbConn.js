const mongoose=require("mongoose");


const dbConn=async()=>{
    try{
        const connDB=await mongoose.connect(process.env.MONGODB_URL)
        if(connDB){
            console.log("data base connect successfully",connDB.connection.host)
        }
    }catch(error){
        console.log(error.message)
    }
}

module.exports=dbConn