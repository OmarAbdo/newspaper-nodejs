//only env configurations
import dotenv from 'dotenv';
const result = dotenv.config(); //dynamically reading environment variables 
if(result.error) {
    throw result.error;
}
const config = result.parsed;
export default config;


