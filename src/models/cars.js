const BaseModel = require("./base");

//inheritance
class CarModel extends BaseModel {
  constructor() {
    super("cars");
    this.select = {
        id: true,
        name: true,
        manufactur: true,
        img: true,
        year: true,
        price: true,
      baggage: true,
      seat:true,
    };
  }
}

module.exports = CarModel
