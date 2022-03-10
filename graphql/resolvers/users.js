const User = require("../../models/User");
 
const bcrypt = require("bcryptjs");
const { SECRET_KEY } = require("../../config");
const jwt = require("jsonwebtoken");
const { UserInputError } = require("apollo-server");
const {validateRegisterInput, validateLoginInput} = require("../../util/validators")

function generateToken(user )
{
    return  jwt.sign(
        {
          id: user.id,
          email: user.email,
          name: user.name,
        },
        SECRET_KEY,
        { expiresIn: "1h" }
      );
}
module.exports = {
  Mutation: {
      async login(_, {email, password})
      {
          const {errors, valid} = validateLoginInput(email, password)

          if(!valid)
          {
            throw new UserInputError('Errors', {errors})
          }
          const user = await User.findOne({email});

          if(!user){
              errors.general = "User not found"
              throw new UserInputError('Wrong Credentials', {errors});
          }
          const match = await bcrypt.compare(password, user.password)
          if(!match){
              errors.general = "Wrong Credentials"
              throw new UserInputError('Wrong Credentials', {errors})
          }
          const token = generateToken(user)

          return {
            ...user._doc,
            id: user._id,
            token,
          };
      },


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

      const token =generateToken(res )
      return {
        ...res._doc,
        id: res._id,
        token,
      };
    },
  },
};
