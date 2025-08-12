const Products = require("../model/productModel");

class productController {
  async getProduct(req, res) {
    try {
      const product = await Products.find();
      res.render("product/index", { product, role: req.user.role,messages: req.flash() });
    } catch (error) {
      console.log(error.message);
    }
  }

  async addProduct(req, res) {
    try {
      return res.render("product/add");
    } catch (error) {
      console.log(error.message);
    }
  }

  async createProduct(req, res) {
    try {
      const { name, size, color, brand, price } = req.body;

      if (!name || !size || !color || !brand || !price) {
        req.flash("error", "all field are required");
        return res.redirect("/add");
      }
      const pdata = new Products({
        name,
        size,
        color,
        brand,
        price,
      });
      const productData = await pdata.save();

      if (productData) {
        req.flash("success", "save the productData");
        return res.redirect("/list");
      } else {
        req.flash("error", "do not save the product");
        return res.redirect("/add");
      }
    } catch (error) {
      console.log(error.message);
    }
  }

  async editProduct(req, res) {
    try {
      const { id } = req.params;
      const products = await Products.findById(id);
      return res.render("product/edit", { products });
    } catch (error) {
      console.log(error.message);
    }
  }

  async updateProduct(req, res) {
    try {
      const { id } = req.params;
      const { name, size, color, price, brand } = req.body;
      await Products.findByIdAndUpdate(id, { name, size, color, price, brand });
      return res.redirect("/list");
    } catch (error) {
      console.log(error);
    }
  }

  async deleteProduct(req, res) {
    try {
      const { id } = req.params;
      await Products.findByIdAndDelete(id);
      return res.redirect("/list");
    } catch (error) {
      console.log(error.message);
    }
  }

  async filterProduct(req, res) {
    let { size, brand, color, price } = req.body;
    const filter = {};

    if (size) {
      size = Array.isArray(size)
        ? size.map((a) => a.toLowerCase())
        : [size.toLowerCase()];
      filter.size = { $in: size };
    }

    if (brand) {
      brand = Array.isArray(brand)
        ? brand.map((b) => b.toLowerCase())
        : [brand.toLowerCase()];
      filter.brand = { $in: brand };
    }

    if (color) {
      color = Array.isArray(color)
        ? color.map((c) => c.toLowerCase())
        : [color.toLowerCase()];
      filter.color = { $in: color };
    }

    if (price) {
      if (price.includes("-")) {
        const [min, max] = price.split("-").map(Number);
        filter.price = { $gte: min, $lte: max };
      } else {
        filter.price = { $gte: Number(price) };
      }
    }

    try {
      const product = await Products.find(filter);
      return res.render("product/index", { product, role: req.user.role });
    } catch (error) {
      console.error(error.message);
      req.flash("error", "Failed to filter products");
      res.redirect("/list");
    }
  }
}
module.exports = new productController();
