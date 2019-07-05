import { check, validationResult } from 'express-validator/check';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

import User from '../../models/user';
import allCountries from '../../util/countries';
import config from '../../util/config';

/**
 * Authentication Class
 * 
 * @description this class is responsible for user authentication which includes the following method  
 * @method signUp               - for user registration 
 * @method logIn                - for user login 
 * @method validate             - validates both login and registration forms' data
 * @method passwordResetToken   - sending email with a reset token to a user to reset his password
 * @method passwordResetForm    - accepting the new user password if he followed the link sent to his email address 
 * @method checkToken           - to validate that users are authentic and can be allowed to visit the desired routes 
 * 
 * @author Omar Abdo
 */
class AuthenticationController {

    signUp(req, res) {
        console.log(req.body);
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.array() });
        }
        bcrypt.hash(req.body.password, 10, function (err, hash) {
            User.build({ ...req.body, password: hash })
                .save()
                .then(result => {
                    res.status(200).json({
                        token: jwt.sign({ userId: result.id }, config.privateKey, { expiresIn: 60 * 60 }),
                        success: 'User Created Successfully',
                        authenticated: true,
                    })
                })
                .catch(error => res.status(422).json({ error: error }))
        });
    }

    logIn(req, res) {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({ errors: errors.array() });
        }
        User.findOne({ where: { email: req.body.email } }).then(user => {
            if (user) {
                bcrypt.compare(req.body.password, user.password, function (err, match) {
                    if (match) {
                        res.status(200).json({
                            token: jwt.sign({ userId: res.id }, config.privateKey, { expiresIn: 60 * 60 }),
                            success: 'User Logged In Successfully',
                            authenticated: true,
                        });
                    } else {
                        res.status(422).json({
                            error: 'Email / password is wrong',
                            authenticated: false,
                        });
                    }
                });
            }
        });
    }

    /**
     * @todo try to avoid duplicating the validation code used for the signUp with the login validation
     */
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
            case 'logIn': {
                return [
                    check('email').isEmail(),
                    check('password', 'password must be 8+ characters contain at least a number, a capital letter and a special character')
                        .isLength({ min: 8 })
                        .custom((value, { req, loc, path }) => {
                            if (value == req.body.email) {
                                throw new Error('Passwords can\'t be the same as email ');
                            } else {
                                return value;
                            }
                        })
                        .matches(/^.*(?=.{8,})((?=.*[!@#$%^&*()\-_=+{};:,<.>]){1})(?=.*\d)((?=.*[a-z]){1})((?=.*[A-Z]){1}).*$/),
                ];
            }
        }
    }

    checkToken(req, res, next) {
        const header = req.headers['authorization'];

        if (typeof header !== 'undefined') {
            req.token = header;
            jwt.verify(req.token, config.privateKey, (err) => {
                if (err) {
                    res.status(403).json({
                        error: "Please Login again 1",
                    })
                } else {
                    next();
                }
            })

        } else {
            res.status(403).json({ error: "Please Login again 2" })
        }
    }

    /**
     * @todo delete this late
     */
    dummyUser(req, res) {
        console.log(req.body);
        res.status(200).json({
            name: 'John Locke',
            email: 'johnlock@liberalism.com',
            password: '123flutteriscool.com',
            country: 'England',
            birthday: '29/08/1632',
        })
    }

}

const authenticationController = new AuthenticationController();
export default authenticationController;