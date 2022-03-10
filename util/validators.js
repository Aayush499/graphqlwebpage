module.exports.validateRegisterInput = (
    name,
    email, password,
    confirmPassword
)=>{
    const errors = {}
    if(name.trim() === ''){
        errors.name = 'Username must not be empty'
    }
    if(email.trim() === ''){
        errors.email = 'email must not be empty'
    }
    else{
        const regEx = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/ ;
        if(!email.match(regEx)){
            errors.email = 'Email must be a valid address';
        }
    }
    if(password.trim() === ''){
        errors.password= 'Password must not be empty'
    }
    else if(password !== confirmPassword)
    {
        errors.confirmPassword = 'Passwords must match'
    }
    return {
        errors,
        valid: Object.keys(errors).length < 1
    }
     
}

module.exports.validateLoginInput = (email, password) => {
    const errors = {}
    if(email.trim() === ''){
        errors.email = 'Username must not be empty'
    }
    if(password.trim() === ''){
        errors.password = 'Password must not be empty'
    }
    return {
        errors,
        valid: Object.keys(errors).length < 1
    }
}