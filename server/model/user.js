const mongoose = require('mongoose');
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken');
const SALT_i = 10;
const config = require('../config/config').get(process.env.NODE_ENV);

userSchema = mongoose.Schema({
    email: {
        type: String, 
        required: true,
        trim: true,
        unique: 1
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    name: {
        type: String,
        maxlength: 100
    },
    lastName: {
        type: String,
        maxlength: 100
    },
    role: {
        type: Number,
        default: 0
    },
    token:{
        type: String
    }
});

userSchema.pre('save', function(next){
    var user = this;
    if(user.isModified('password')){
        bcrypt.genSalt(SALT_i, (err, salt)=>{
            if(err) return next(err);
            bcrypt.hash(user.password, salt, (err, hash)=>{
                if(err) return next(err);
                user.password = hash;
                next();
            });
        })
    }else{
        next();
    }
})

userSchema.methods.comparePWD = function(inputPWD, cb) {
    bcrypt.compare(inputPWD, this.password, (err, isMatch) => {
        if(err) return cb(err);
        cb(null, isMatch);
    })
}

userSchema.methods.generateToken = function(cb) {
    var user = this;
    var token = jwt.sign(user._id.toHexString(), config.SECRET);
    user.token = token;
    user.save((err, user) => {
        if(err) return cb(err);
        cb(null, user);
    });
}

userSchema.statics.findByToken = function(token, cb){
    var user = this;
    jwt.verify(token, config.SECRET,(err, decode) => {
        user.findOne({_id: decode, token: token}, (err, user) => {
            if(err) return cb(err);
            cb(null, user);
        })
    })
}

userSchema.methods.deleteToken = function(token, cb){
    var user = this;
    user.updateOne({$unset:{token:1}}, (err, user) => {
        if(err) return cb(err);
        cb(null, user)
    })
}

const User = mongoose.model('User', userSchema);

module.exports = { User };