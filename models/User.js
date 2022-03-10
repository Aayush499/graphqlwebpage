const { model, Schema } = require('mongoose')

const userSchema  = new Schema ({
    email: {
        type : String,
        required : true,
        unique: true
    },
    password: {
		type: String,
		required: true
	},
    company: {
		type: String,
		//required: true
	},
    name: {
		type: String,
		required: true
	},
    createdAt:
    {
        type: String
    }
})

module.exports = model('User',  userSchema )