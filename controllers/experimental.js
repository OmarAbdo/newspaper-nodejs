import jwt from 'jsonwebtoken';
let dummyUser = {
    id: 1,
    fullName: "Omar Abdo",
    email: "omareabdo@gmail.com",
    password: "123456",    
};
let dummyKey = {
    tokenKey: "someStringTokenSecret",
}

class ExperimentalController {
    createJWT(req, res) {
        let token = jwt.sign({ userId: dummyUser.id }, dummyKey.tokenKey);       
        return res.status(200).send({
            msg: 'All good, Captain!',
            token: token,
        });
    }
}

const experimentalController = new ExperimentalController();
export default experimentalController;