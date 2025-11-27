import bcrypt from 'bcrypt'

const SALT_ROUNDS = 12


const hashStrings = async (string)=>{

    return bcrypt.hash(string, SALT_ROUNDS)
}

export default hashStrings;