const mongoose=require("mongoose");
const Schema=mongoose.Schema

const ProductSchema=new Schema({
     name:{
        type:String,
        required:true
    },
    size:{
        type:String,
        required:true
    },
    color:{
        type:String,
        required:true
    },
    price:{
        type:String,
        required:true
    },
    brand:{
        type:String,
        required:true
    },
    
},{timestamps:true})

const productTest=mongoose.model("Products",ProductSchema)
module.exports=productTest