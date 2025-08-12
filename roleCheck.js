// middleware/roleMiddleware.js
function allowedRoles(...roles) {
    return async (req, res, next) => {
        try {
            // Check if user is logged in
            if (!req.user) {
                req.flash("error", "Please log in to continue");
                return res.redirect("/login");
            }

            // Check if user's role is in the allowed list
            if (!roles.includes(req.user.role)) {
                req.flash("error", "Access Denied");
                return res.redirect("/list");
            }

            // Pass control to next middleware or route
            next();
        } catch (error) {
            console.error("Role check failed:", error);
            req.flash("error", "Something went wrong");
            return res.redirect("/register");
        }
    };
}

module.exports = allowedRoles;
