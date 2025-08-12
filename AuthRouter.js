const express=require("express");
const AuthController=require("../controller/AuthController");
const AuthCheck=require("../middleware/AuthCheck");
const productController=require("../controller/productController");
const allowedRoles=require("../middleware/roleCheck");
const router=express.Router()

router.get("/register",AuthController.registerPage);
router.post("/register",AuthController.Register);
router.get("/verify_otp",AuthController.verify_otpPage);
router.post("/verify_otp",AuthController.Verify_otp);
router.get("/login",AuthController.loginPage);
router.post("/login",AuthController.Login);

router.get("/refresh-token",AuthController.refreshToken);

router.get("/dashboard",AuthCheck,AuthController.Auth,AuthController.dashboard);
router.get("/logout",AuthController.logout);

router.get("/update_password",AuthCheck,AuthController.updatePassword);
router.post("/update_password",AuthCheck,AuthController.updatePasswordPage);


//product

router.get("/list",AuthCheck,productController.getProduct);
router.get("/add",AuthCheck,allowedRoles("admin", "manager","employee"),productController.addProduct);
router.post("/create/product",AuthCheck,allowedRoles("admin", "manager","employee"),productController.createProduct);
router.get("/edit/:id",AuthCheck,allowedRoles("admin", "manager"),productController.editProduct);
router.post("/update/:id",AuthCheck,allowedRoles("admin", "manager"),productController.updateProduct);
router.get("/delete/:id",AuthCheck,allowedRoles("admin"),productController.deleteProduct);
router.post("/filter",AuthCheck,productController.filterProduct);








module.exports=router