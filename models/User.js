const mangoose = require('mongoose'); 

const User = mangoose.model('User', {
    name: String,
    email: String,
    password: String
});

module.exports = User