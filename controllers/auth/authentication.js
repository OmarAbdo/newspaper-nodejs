import User from '../../models/user';
import { check, validationResult } from 'express-validator/check';
import allCountries from '../../util/countries';
import bcrypt from 'bcrypt';

class AuthenticationController {
    signUp(req, res) {
        console.log(req.body);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.array() });
        }
        //create jwt here
      
        bcrypt.hash(req.body.password, 10, function(err, hash) {
            User.build({ ...req.body, password: hash})            
            .save()
                .then(result => res.status(200).json({success: 'User Created Successfully',}))
                .catch(error => res.status(422).json({ error: error }))
        });
       
    }

    validate(method) {
        switch (method) {
            case 'signUp': {
                return [
                    check('name').isLength({ min: 4 }).withMessage('name must be longer than 4 characters'),
                    check('name').isLength({ max: 36 }).withMessage('name must be shorter than 36 characters'),
                    check('email').isEmail(),
                    check('email').custom(value => {
                        return User.findOne({ where: { email: value } }).then(user => {
                            if (user) {
                                return Promise.reject('E-mail already exists');
                            }
                        })
                    }),
                    check('password', 'password must be 8+ characters contain at least a number, a capital letter and a special character')
                        .isLength({ min: 8 })
                        .custom((value, { req, loc, path }) => {
                            if (value == req.body.name) {
                                throw new Error('Passwords can\'t be the same as name ');
                            } else {
                                return value;
                            }
                        })
                        .custom((value, { req, loc, path }) => {
                            if (value == req.body.email) {
                                throw new Error('Passwords can\'t be the same as email ');
                            } else {
                                //hash password here
                                return value;
                            }
                        })
                        .matches(/^.*(?=.{8,})((?=.*[!@#$%^&*()\-_=+{};:,<.>]){1})(?=.*\d)((?=.*[a-z]){1})((?=.*[A-Z]){1}).*$/),
                    check('country').custom(value => {
                        if (!allCountries.includes(value)) {
                            throw new Error('Please select a valid country');
                        } else {
                            return value;
                        }

                    }),
                    check('birthday').custom(value => {
                        if (!value || value.length == 0) {
                            throw new Error('You must provide a valid birthday');
                        }
                        if (!value.match(/(0[1-9]|[12][0-9]|3[01])[- /.](0[1-9]|1[012])[- /.](19|20)\d\d/)) {
                            throw new Error('Please enter dd/mm/yyyy');
                        }
                        else {
                            return value;
                        }
                    })
                ]
            }
        }
    }

}

const authenticationController = new AuthenticationController();
export default authenticationController;