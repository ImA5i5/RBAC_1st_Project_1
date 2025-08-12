const mongoose=require("mongoose")
const Schema=mongoose.Schema


const AuthSchema=new Schema({
    name:{
        type:String,
        required:true
    },
    email:{
        type:String,
        required:true
    },
    is_verify:{
        type:Boolean,
        default:false
    },
    password:{
        type:String,
        required:true
    },
    phone:{
        type:Number,
        required:true
    },
    role:{
    type: String,
    enum: ["admin","manager","employee"],
    default: 'admin'
  },
},{
    timestamps:true
})

const AuthTest=mongoose.model("User",AuthSchema);
module.exports=AuthTest