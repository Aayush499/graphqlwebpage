const { model, Schema } = require('mongoose')

const postSchema  = new Schema ({
    body: String,
    name: String,
    createdAt: String,
    comments: [
        {
            body: String,
            name: String,
            createdAt :  String
        }
    ],
    likes: [
        {
            name : String,
            createdAt: String
        }
    ],
    user:{
        type: Schema.Types.ObjectId,
        ref: 'users'
    }
})

module.exports = model('Post',  postSchema )