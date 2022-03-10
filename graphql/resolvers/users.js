const User = require("../../models/User");
 
const bcrypt = require("bcryptjs");
const { SECRET_KEY } = require("../../config");
const jwt = require("jsonwebtoken");
const { UserInputError } = require("apollo-server");
const {validateRegisterInput} = require("../../util/validators")
module.exports = {
  Mutation: {
    async register(
      _,
      { registerInput: { name, email, password, confirmPassword } }
    ) {
      //VALIDATE USER DATA
      const {valid, errors} = validateRegisterInput(name, email, password, confirmPassword);
      if(!valid){
          throw new UserInputError('Errors', {errors})
      }
      
      //MAKE SURE USER DOESNT EXIST
      const user = await User.findOne({ email });
      if (user) { 
        throw new UserInputError("email already in use", {
          email: "This email is taken",
          
        });
      }
      // HASH PASSWORD
      password = await bcrypt.hash(password, 12);

      const newUser = new User({
        email,
        name,
        password,
        createdAt: new Date().toISOString(),
      });

      const res = await newUser.save();

      const token = jwt.sign(
        {
          id: res.id,
          email: res.email,
          name: res.name,
        },
        SECRET_KEY,
        { expiresIn: "1h" }
      );
      return {
        ...res._doc,
        id: res._id,
        token,
      };
    },
  },
};
